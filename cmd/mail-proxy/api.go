package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// apiClient 调用主项目（Cloudflare Workers）的 HTTP API。
// 代理本身不保存任何邮件或用户数据：所有读写都直接转成对主 API 的请求。
type apiClient struct {
	base   string // 如 https://api.cee.edu.pl
	origin string // 主 API 生产环境的 CSRF 校验要求写请求带 Origin，取值须在其 FRONTEND_URL 白名单内
	http   *http.Client

	authMode     string // "login" | "app-password"
	appLoginPath string

	// proxySecret：与主 API 的 Workers secret PROXY_SHARED_SECRET 相同。非空时每个请求带 X-Proxy-Auth，
	// 主 API 据此信任 X-Client-IP（真实 IMAP/SMTP 客户端 IP，用于按 IP 限流与「最近使用 IP」）。
	proxySecret string

	// 登录令牌缓存（只在内存里，进程重启即清空）。
	// 同一用户的多个 IMAP/SMTP 连接（iPhone 会同时开好几个）共用一个主 API 会话，
	// 否则每个连接各登录一次：主 API 的 /login 会删除该用户的其他会话，互相踢下线。
	mu     sync.Mutex
	tokens map[string]cachedToken
}

type cachedToken struct {
	token   string
	mailbox *apiMailbox
	expires time.Time
}

// apiMailbox：用某个邮箱地址（而不是平台账号邮箱）登录时，主 API 返回的单邮箱范围。
// nil 表示整个账户。
type apiMailbox struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

func sameMailbox(a, b *apiMailbox) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.ID == b.ID
}

type ctxKey int

const clientIPKey ctxKey = 1

// withClientIP 把 IMAP/SMTP 客户端的真实 IP 放进 ctx，请求主 API 时作为 X-Client-IP 转交
func withClientIP(ctx context.Context, ip string) context.Context {
	if ip == "" {
		return ctx
	}
	return context.WithValue(ctx, clientIPKey, ip)
}

var errAuthFailed = errors.New("authentication failed")

// apiError 保留主 API 的状态码与错误码，便于映射成 IMAP/SMTP 回复
type apiError struct {
	Status int
	Code   string
	Msg    string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("API %d %s: %s", e.Status, e.Code, e.Msg)
}

func newAPIClient(base, origin, authMode, appLoginPath string) *apiClient {
	return &apiClient{
		base:         strings.TrimRight(base, "/"),
		origin:       origin,
		http:         &http.Client{Timeout: 60 * time.Second},
		authMode:     authMode,
		appLoginPath: appLoginPath,
		tokens:       make(map[string]cachedToken),
	}
}

func credKey(user, pass string) string {
	h := sha256.Sum256([]byte(strings.ToLower(user) + "\x00" + pass))
	return hex.EncodeToString(h[:])
}

// login 用用户名/密码换取主 API 的会话令牌（有缓存）。
// 缓存键含用户名：同一个应用密码用「平台账号邮箱」和「某个邮箱地址」登录是两个范围不同的会话，互不复用。
// 返回的 mailbox 非 nil 表示单邮箱登录（只在 app-password 模式下由主 API 返回）。
func (c *apiClient) login(ctx context.Context, user, pass string, forceRefresh bool) (string, *apiMailbox, error) {
	key := credKey(user, pass)
	if !forceRefresh {
		c.mu.Lock()
		t, ok := c.tokens[key]
		c.mu.Unlock()
		if ok && time.Now().Before(t.expires) {
			return t.token, t.mailbox, nil
		}
	}

	path := "/api/auth/login"
	body := map[string]string{"email": user, "password": pass}
	if c.authMode == "app-password" {
		path = c.appLoginPath
		body = map[string]string{"email": user, "appPassword": pass}
	}
	var out struct {
		SessionToken string      `json:"sessionToken"`
		Token        string      `json:"token"`
		Mailbox      *apiMailbox `json:"mailbox"`
	}
	err := c.doJSON(ctx, "", http.MethodPost, path, body, &out)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && (ae.Status == 401 || ae.Status == 403) {
			return "", nil, errAuthFailed
		}
		return "", nil, err
	}
	tok := out.SessionToken
	if tok == "" {
		tok = out.Token
	}
	if tok == "" {
		return "", nil, errors.New("API 登录响应里没有令牌")
	}
	mb := out.Mailbox
	if c.authMode != "app-password" || (mb != nil && mb.ID == "") {
		mb = nil
	}
	c.mu.Lock()
	c.tokens[key] = cachedToken{token: tok, mailbox: mb, expires: time.Now().Add(12 * time.Hour)}
	// 顺手清理过期项，避免长时间运行后无限增长
	for k, v := range c.tokens {
		if time.Now().After(v.expires) {
			delete(c.tokens, k)
		}
	}
	c.mu.Unlock()
	return tok, mb, nil
}

func (c *apiClient) forget(user, pass string) {
	c.mu.Lock()
	delete(c.tokens, credKey(user, pass))
	c.mu.Unlock()
}

func (c *apiClient) newRequest(ctx context.Context, token, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	req.Header.Set("User-Agent", "mail-proxy")
	if c.proxySecret != "" {
		req.Header.Set("X-Proxy-Auth", c.proxySecret)
	}
	if ip, _ := ctx.Value(clientIPKey).(string); ip != "" {
		req.Header.Set("X-Client-IP", ip)
	}
	return req, nil
}

func (c *apiClient) do(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		json.Unmarshal(b, &e)
		return nil, &apiError{Status: resp.StatusCode, Code: e.Code, Msg: e.Error}
	}
	return resp, nil
}

func (c *apiClient) doJSON(ctx context.Context, token, method, path string, in, out interface{}) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := c.newRequest(ctx, token, method, path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// ---------- 数据结构（与 api/src/routes/email.ts 的响应保持一致） ----------

type apiAccount struct {
	ID        string `json:"id"`
	Name      string `json:"name"` // 邮箱地址
	Type      string `json:"type"`
	ExpiresAt *int64 `json:"expiresAt"`
}

// flexTime 兼容 drizzle 时间戳被序列化成 ISO 字符串或秒级/毫秒级数字
type flexTime struct{ time.Time }

func (t *flexTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		if n > 1e12 {
			t.Time = time.UnixMilli(int64(n))
		} else {
			t.Time = time.Unix(int64(n), 0)
		}
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if v, err := time.Parse(layout, s); err == nil {
			t.Time = v
			return nil
		}
	}
	return nil
}

type apiEmailSummary struct {
	ID          uint32   `json:"id"`
	AccountID   string   `json:"accountId"`
	Sender      string   `json:"sender"`
	SenderEmail string   `json:"senderEmail"`
	Subject     string   `json:"subject"`
	Unread      bool     `json:"unread"`
	Starred     bool     `json:"starred"`
	ReceivedAt  flexTime `json:"receivedAt"`
	// 已发送列表的字段
	To          string   `json:"to"`
	SentAt      flexTime `json:"sentAt"`
	CreatedAt   flexTime `json:"createdAt"`
	FromAddress string   `json:"fromAddress"` // /api/email/sent-emails 每行的发件邮箱地址
	// 若主 API 将来在列表里返回原文大小（见 imap-api-needs.md），可避免为 RFC822.SIZE 下载原文
	SizeBytes int64 `json:"sizeBytes"`
}

type apiListResp struct {
	Emails     []apiEmailSummary `json:"emails"`
	NextCursor *string           `json:"nextCursor"`
	HasMore    bool              `json:"hasMore"`
}

type apiEmailDetail struct {
	ID          uint32            `json:"id"`
	Sender      string            `json:"sender"`
	SenderEmail string            `json:"senderEmail"`
	Subject     string            `json:"subject"`
	TextContent *string           `json:"textContent"`
	HTMLContent *string           `json:"htmlContent"`
	Headers     map[string]any    `json:"headers"`
	ReceivedAt  flexTime          `json:"receivedAt"`
	Attachments []json.RawMessage `json:"attachments"`
	// 已发送详情
	To     string   `json:"to"`
	Cc     *string  `json:"cc"`
	SentAt flexTime `json:"sentAt"`
}

// ---------- 业务调用：全部是对现有接口的直接转发 ----------

func (c *apiClient) me(ctx context.Context, token string) (impersonated bool, err error) {
	var out struct {
		ImpersonatedBy json.RawMessage `json:"impersonatedBy"`
	}
	if err := c.doJSON(ctx, token, http.MethodGet, "/api/auth/me", nil, &out); err != nil {
		return false, err
	}
	s := strings.TrimSpace(string(out.ImpersonatedBy))
	return s != "" && s != "null", nil
}

func (c *apiClient) accounts(ctx context.Context, token string) ([]apiAccount, error) {
	var out struct {
		Accounts []apiAccount `json:"accounts"`
	}
	err := c.doJSON(ctx, token, http.MethodGet, "/api/email/accounts", nil, &out)
	return out.Accounts, err
}

// listPage 拉一页列表。path 例如 /api/email/emails、/api/email/accounts/{id}/emails
func (c *apiClient) listPage(ctx context.Context, token, path string, q url.Values) (*apiListResp, error) {
	var out apiListResp
	p := path
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	err := c.doJSON(ctx, token, http.MethodGet, p, nil, &out)
	return &out, err
}

func (c *apiClient) raw(ctx context.Context, token string, id uint32, maxBytes int64) ([]byte, error) {
	req, err := c.newRequest(ctx, token, http.MethodGet, fmt.Sprintf("/api/email/emails/%d/raw", id), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

func (c *apiClient) detail(ctx context.Context, token string, id uint32) (*apiEmailDetail, error) {
	var out struct {
		Email apiEmailDetail `json:"email"`
	}
	err := c.doJSON(ctx, token, http.MethodGet, fmt.Sprintf("/api/email/emails/%d", id), nil, &out)
	return &out.Email, err
}

func (c *apiClient) sentDetail(ctx context.Context, token string, id uint32) (*apiEmailDetail, error) {
	var out struct {
		Email apiEmailDetail `json:"email"`
	}
	err := c.doJSON(ctx, token, http.MethodGet, fmt.Sprintf("/api/email/sent-emails/%d", id), nil, &out)
	return &out.Email, err
}

func (c *apiClient) setRead(ctx context.Context, token string, id uint32, read bool) error {
	return c.doJSON(ctx, token, http.MethodPost, fmt.Sprintf("/api/email/emails/%d/read", id), map[string]bool{"unread": !read}, nil)
}

func (c *apiClient) setStarred(ctx context.Context, token string, id uint32, starred bool) error {
	return c.doJSON(ctx, token, http.MethodPost, fmt.Sprintf("/api/email/emails/%d/star", id), map[string]bool{"starred": starred}, nil)
}

func (c *apiClient) deleteEmail(ctx context.Context, token string, id uint32) error {
	return c.doJSON(ctx, token, http.MethodDelete, fmt.Sprintf("/api/email/emails/%d", id), nil, nil)
}

type uploadedAttachment struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Path string `json:"path,omitempty"`
	Size int64  `json:"size"`
}

func (c *apiClient) uploadAttachment(ctx context.Context, token, filename, contentType string, data []byte) (*uploadedAttachment, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name="file"; filename=%q`, filename)}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	h["Content-Type"] = []string{contentType}
	part, err := mw.CreatePart(h)
	if err != nil {
		return nil, err
	}
	part.Write(data)
	mw.Close()
	req, err := c.newRequest(ctx, token, http.MethodPost, "/api/email/upload-attachment", &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out uploadedAttachment
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Name == "" {
		out.Name = filename
	}
	if out.Size == 0 {
		out.Size = int64(len(data))
	}
	return &out, nil
}

// sendRequest 对应主 API POST /api/email/send（审查 2026-10-09 M10 之后的版本）：
// to / cc / bcc 是地址数组（每项最多 100 个）；bcc 只进信封，主 API 不会把它写进信头；
// inReplyTo（1 个 <id>）/ references（最多 50 个 <id>，空格分隔）不能含换行。
type sendRequest struct {
	AccountID   string               `json:"accountId"`
	To          []string             `json:"to"`
	Cc          []string             `json:"cc,omitempty"`
	Bcc         []string             `json:"bcc,omitempty"`
	InReplyTo   string               `json:"inReplyTo,omitempty"`
	References  string               `json:"references,omitempty"`
	Subject     string               `json:"subject"`
	HTML        string               `json:"html"`
	Attachments []uploadedAttachment `json:"attachments,omitempty"`
}

func (c *apiClient) send(ctx context.Context, token string, req *sendRequest) error {
	return c.doJSON(ctx, token, http.MethodPost, "/api/email/send", req, nil)
}
