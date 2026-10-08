package main

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"
)

// userSession 是一个已登录连接的会话状态，只活在这个连接的内存里。
type userSession struct {
	api      *apiClient
	user     string
	pass     string // 仅用于主 API 令牌失效时重新登录；连接断开即丢弃
	token    string
	readOnly bool // 管理员模拟会话：只读，任何写操作都拒绝
	ip       string
	// mailbox 非 nil：用户名填的是名下某个邮箱地址，只能看到 / 操作这一个邮箱
	//（INBOX/Sent/Trash 只含该邮箱，没有 Accounts/ 子目录，SMTP 发件人只能是该地址）
	mailbox *apiMailbox

	mu       sync.Mutex
	accounts []apiAccount
	accTime  time.Time
}

func authenticate(ctx context.Context, api *apiClient, limiter *loginLimiter, remoteIP, user, pass string) (*userSession, error) {
	user = strings.TrimSpace(user)
	if user == "" || pass == "" {
		return nil, errAuthFailed
	}
	if !limiter.allow(remoteIP, user) {
		log.Printf("登录被限流: ip=%s user=%s", remoteIP, user)
		return nil, errRateLimited
	}
	tok, mb, err := api.login(withClientIP(ctx, remoteIP), user, pass, false)
	if err != nil {
		if errors.Is(err, errAuthFailed) {
			limiter.fail(remoteIP, user)
			log.Printf("登录失败: ip=%s user=%s", remoteIP, user)
		} else {
			log.Printf("登录时主 API 出错: ip=%s user=%s err=%v", remoteIP, user, err)
		}
		return nil, err
	}
	s := &userSession{api: api, user: user, pass: pass, token: tok, ip: remoteIP, mailbox: mb}
	ro, err := s.meCheck(ctx)
	if err != nil {
		return nil, err
	}
	s.readOnly = ro
	limiter.success(remoteIP, user)
	log.Printf("登录成功: ip=%s user=%s readOnly=%v scope=%s", remoteIP, user, ro, s.scopeName())
	return s, nil
}

func (s *userSession) scopeName() string {
	if s.mailbox == nil {
		return "account"
	}
	return "mailbox:" + s.mailbox.Address
}

func (s *userSession) meCheck(ctx context.Context) (bool, error) {
	var ro bool
	err := s.call(ctx, func(tok string) error {
		var err error
		ro, err = s.api.me(ctx, tok)
		return err
	})
	return ro, err
}

// call 执行一次主 API 调用；令牌失效（401）时重新登录一次再试。
func (s *userSession) call(ctx context.Context, f func(token string) error) error {
	err := f(s.token)
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == 401 && s.pass != "" {
		tok, mb, lerr := s.api.login(withClientIP(ctx, s.ip), s.user, s.pass, true)
		if lerr != nil {
			return lerr
		}
		if !sameMailbox(mb, s.mailbox) {
			// 范围变了（例如该邮箱已删除 / 过期）：不能沿用本连接的范围，让客户端重新登录
			s.api.forget(s.user, s.pass)
			return errAuthFailed
		}
		s.token = tok
		return f(tok)
	}
	return err
}

func (s *userSession) getAccounts(ctx context.Context) ([]apiAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accounts != nil && time.Since(s.accTime) < time.Minute {
		return s.accounts, nil
	}
	var accs []apiAccount
	err := s.call(ctx, func(tok string) error {
		var err error
		accs, err = s.api.accounts(ctx, tok)
		return err
	})
	if err != nil {
		return nil, err
	}
	if s.mailbox != nil {
		// 单邮箱登录：只保留这一个邮箱（已删除 / 过期则为空）
		var only []apiAccount
		for _, a := range accs {
			if a.ID == s.mailbox.ID {
				only = append(only, a)
			}
		}
		accs = only
		if accs == nil {
			accs = []apiAccount{}
		}
	}
	s.accounts, s.accTime = accs, time.Now()
	return accs, nil
}

var errRateLimited = errors.New("too many failed logins, try again later")

// loginLimiter：按来源 IP 与按用户名分别计数的登录失败限流（内存，进程重启即清空）。
// 主 API 自己也有登录限流与账户锁定，但它看到的来源 IP 全是这台 VPS，
// 所以必须在代理这一层按真实客户端 IP 先挡一道，否则一个人爆破就会把所有用户一起锁死。
type loginLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	maxFails int
	ip       map[string][]time.Time
	user     map[string][]time.Time
}

func newLoginLimiter(maxFails int, window time.Duration) *loginLimiter {
	return &loginLimiter{window: window, maxFails: maxFails, ip: map[string][]time.Time{}, user: map[string][]time.Time{}}
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func (l *loginLimiter) allow(ip, user string) bool {
	if l.maxFails <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.window)
	user = strings.ToLower(user)
	l.ip[ip] = prune(l.ip[ip], cutoff)
	l.user[user] = prune(l.user[user], cutoff)
	if len(l.ip[ip]) == 0 {
		delete(l.ip, ip)
	}
	if len(l.user[user]) == 0 {
		delete(l.user, user)
	}
	// 按用户名的阈值放宽一倍，避免攻击者轻易把某个用户锁死
	return len(l.ip[ip]) < l.maxFails && len(l.user[user]) < l.maxFails*2
}

func (l *loginLimiter) fail(ip, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.ip[ip] = append(l.ip[ip], now)
	u := strings.ToLower(user)
	l.user[u] = append(l.user[u], now)
}

func (l *loginLimiter) success(ip, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ip, ip)
}
