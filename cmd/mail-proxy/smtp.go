package main

// SMTP 提交（465 隐式 TLS / 587 STARTTLS）：认证后把客户端交来的 MIME 拆成主 API /send 的参数。
// 不做任何外发投递，所有发信（含每日限额、发信权限、发件通道选择）都由主 API 决定。

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type submissionBackend struct {
	cfg      *proxyConfig
	api      *apiClient
	limiter  *loginLimiter
	maxRcpts int
}

func (b *submissionBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	ip := ""
	if c != nil && c.Conn() != nil {
		if a, ok := c.Conn().RemoteAddr().(*net.TCPAddr); ok {
			ip = a.IP.String()
		}
	}
	return &submissionSession{b: b, ip: ip}, nil
}

type submissionSession struct {
	b         *submissionBackend
	ip        string
	us        *userSession
	accountID string
	from      string
	rcpts     []string
}

var _ smtp.AuthSession = (*submissionSession)(nil)

func (s *submissionSession) AuthMechanisms() []string { return []string{sasl.Plain, sasl.Login} }

func (s *submissionSession) Auth(mech string) (sasl.Server, error) {
	login := func(user, pass string) error {
		c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		us, err := authenticate(c, s.b.api, s.b.limiter, s.ip, user, pass)
		if err != nil {
			switch {
			case errors.Is(err, errRateLimited):
				return &smtp.SMTPError{Code: 454, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Too many failed logins, try again later"}
			case errors.Is(err, errAuthFailed):
				return smtp.ErrAuthFailed
			default:
				return &smtp.SMTPError{Code: 454, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Temporary authentication failure"}
			}
		}
		if us.readOnly {
			// 管理员模拟会话只读：不允许以用户身份发信
			return &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Read-only session cannot send mail"}
		}
		s.us = us
		return nil
	}
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if identity != "" && identity != username {
				return errors.New("identities not supported")
			}
			return login(username, password)
		}), nil
	case sasl.Login:
		return newLoginServer(login), nil
	}
	return nil, smtp.ErrAuthUnknownMechanism
}

func (s *submissionSession) Mail(from string, opts *smtp.MailOptions) error {
	if s.us == nil {
		return smtp.ErrAuthRequired
	}
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accs, err := s.us.getAccounts(c)
	if err != nil {
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Backend temporarily unavailable"}
	}
	addr := strings.ToLower(strings.Trim(from, "<> "))
	for _, a := range accs {
		if strings.EqualFold(a.Name, addr) {
			s.accountID, s.from = a.ID, a.Name
			return nil
		}
	}
	// 只能用自己名下（且未过期）的邮箱发信，防止冒用他人地址
	return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sender address not owned by authenticated user"}
}

// apiMaxRecipients：主 API /send 的 to / cc / bcc 每项最多 100 个地址；代理的 MAX_RECIPIENTS 不得超过它
const apiMaxRecipients = 100

// 与主 API 的 z.string().email()（zod 4）同一套规则，格式不合法的地址在 RCPT 阶段就拒绝，
// 否则整封信到 /send 才会被 400 退回。
var rcptRe = regexp.MustCompile(`^[A-Za-z0-9_'+\-.]*[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)

func validRcpt(addr string) bool {
	return len(addr) <= 320 && !strings.HasPrefix(addr, ".") && !strings.Contains(addr, "..") && rcptRe.MatchString(addr)
}

func (s *submissionSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	if s.accountID == "" {
		return &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "MAIL first"}
	}
	addr := strings.Trim(to, "<> ")
	if !validRcpt(addr) {
		return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 1, 3}, Message: "Bad recipient address syntax"}
	}
	for _, r := range s.rcpts {
		if strings.EqualFold(r, addr) {
			return nil // 重复的 RCPT 不重复计数
		}
	}
	if len(s.rcpts) >= s.b.maxRcpts {
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "Too many recipients"}
	}
	s.rcpts = append(s.rcpts, addr)
	return nil
}

// splitRecipients 按信封决定 to / cc / bcc：
//   - 信封是实际投递的唯一依据：信头里有、信封里没有的地址不发（有的客户端把密送拆成单独一次提交，
//     那次的信头仍是原来的 To/Cc；若按信头发，To/Cc 里的人会收到第二封）。
//   - 信封里的地址出现在信头 To / Cc 中的，保持 To / Cc；其余全部作为 bcc（不会出现在信头里）。
//   - 主 API 要求 to 非空：全是密送时（典型的 undisclosed-recipients），To 填发件人自己，
//     发件人会收到一份副本，收件人只看到 To: 发件人，不会互相看到。
func splitRecipients(from string, rcpts, hdrTo, hdrCc []string) (to, cc, bcc []string) {
	in := func(list []string, a string) bool {
		for _, x := range list {
			if strings.EqualFold(x, a) {
				return true
			}
		}
		return false
	}
	for _, r := range rcpts {
		switch {
		case in(hdrTo, r):
			to = append(to, r)
		case in(hdrCc, r):
			cc = append(cc, r)
		default:
			bcc = append(bcc, r)
		}
	}
	if len(to) == 0 {
		to = []string{from}
	}
	return to, cc, bcc
}

func (s *submissionSession) Data(r io.Reader) error {
	if s.us == nil || s.accountID == "" || len(s.rcpts) == 0 {
		return &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "Bad sequence of commands"}
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		if err == smtp.ErrDataTooLarge {
			return err
		}
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 2}, Message: "Error reading message"}
	}
	msg, err := parseSubmission(buf.Bytes())
	if err != nil {
		return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "Cannot parse message"}
	}

	c, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 附件先上传到主 API，拿回只属于本用户的引用
	var atts []uploadedAttachment
	for _, a := range msg.Attachments {
		var up *uploadedAttachment
		err := s.us.call(c, func(tok string) error {
			var err error
			up, err = s.b.api.uploadAttachment(c, tok, a.Filename, a.ContentType, a.Data)
			return err
		})
		if err != nil {
			log.Printf("附件上传失败 user=%s file=%s: %v", s.us.user, a.Filename, err)
			return smtpErrFromAPI(err)
		}
		atts = append(atts, *up)
	}

	// 整封信只调用一次 /send（审查 M10）：要么整封成功，要么整封失败，客户端重发不会让部分收件人收到两封。
	to, cc, bcc := splitRecipients(s.from, s.rcpts, msg.To, msg.Cc)
	req := &sendRequest{AccountID: s.accountID, To: to, Cc: cc, Bcc: bcc,
		InReplyTo: msg.InReplyTo, References: msg.References,
		Subject: msg.Subject, HTML: msg.HTML, Attachments: atts}
	if err := s.us.call(c, func(tok string) error { return s.b.api.send(c, tok, req) }); err != nil {
		log.Printf("发信失败 user=%s from=%s rcpts=%d: %v", s.us.user, s.from, len(s.rcpts), err)
		return smtpErrFromAPI(err)
	}
	log.Printf("SMTP 提交 user=%s from=%s to=%d cc=%d bcc=%d", s.us.user, s.from, len(to), len(cc), len(bcc))
	return nil
}

func smtpErrFromAPI(err error) error {
	var ae *apiError
	if errors.As(err, &ae) {
		switch {
		case ae.Status == 429:
			// 配额 / 频率（DAILY_SEND_LIMIT、HOURLY_SEND_LIMIT、NEW_USER_SEND_LIMIT、SEND_LIMITER）：整封临时失败，
			// 客户端稍后重发。/send 是整封一次调用，429 时一封都没发出去，重发不会重复。
			// 回复只用 ASCII（主 API 的中文错误信息不直接塞进 SMTP 回复，部分客户端显示乱码），带上错误码便于排查
			msg := "Sending quota exceeded, try again later"
			if ae.Code != "" {
				msg += " (" + ae.Code + ")"
			}
			return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: msg}
		case ae.Code == "SEND_NOT_ALLOWED" || ae.Code == "IMPERSONATION_READ_ONLY" || ae.Code == "DOMAIN_DISABLED" || ae.Code == "SEND_SUSPENDED":
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sending not allowed for this mailbox"}
		case ae.Status == 400 || ae.Status == 404 || ae.Status == 410 || ae.Status == 413 || ae.Status == 422:
			msg := ae.Msg
			if msg == "" {
				msg = "Message rejected"
			}
			return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: msg}
		}
	}
	return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Backend temporarily unavailable"}
}

func (s *submissionSession) Reset() {
	s.accountID, s.from, s.rcpts = "", "", nil
}

func (s *submissionSession) Logout() error { return nil }

// LOGIN 机制（部分老客户端/Outlook 只会 AUTH LOGIN）
type loginServer struct {
	auth            func(user, pass string) error
	user            string
	gotUser, gotPwd bool
}

func newLoginServer(auth func(user, pass string) error) sasl.Server {
	return &loginServer{auth: auth}
}

func (a *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch {
	case !a.gotUser && response == nil:
		return []byte("Username:"), false, nil
	case !a.gotUser:
		a.user, a.gotUser = string(response), true
		return []byte("Password:"), false, nil
	case !a.gotPwd:
		a.gotPwd = true
		return nil, true, a.auth(a.user, string(response))
	}
	return nil, true, errors.New("unexpected response")
}
