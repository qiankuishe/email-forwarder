package main

// SMTP 提交（465 隐式 TLS / 587 STARTTLS）：认证后把客户端交来的 MIME 拆成主 API /send 的参数。
// 不做任何外发投递，所有发信（含每日限额、发信权限、发件通道选择）都由主 API 决定。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

func (s *submissionSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	if s.accountID == "" {
		return &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "MAIL first"}
	}
	if len(s.rcpts) >= s.b.maxRcpts {
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "Too many recipients"}
	}
	s.rcpts = append(s.rcpts, strings.Trim(to, "<> "))
	return nil
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

	// 主 API 的 /send 只接受单个收件人：逐个调用。抄送/密送收件人同样各发一封
	//（收件人看到的 To 是自己，原始 To/Cc 头不会保留，见 imap-api-needs.md）。
	var sent, failed []string
	var lastErr error
	for _, rcpt := range s.rcpts {
		req := &sendRequest{AccountID: s.accountID, To: rcpt, Subject: msg.Subject, HTML: msg.HTML, Attachments: atts}
		err := s.us.call(c, func(tok string) error { return s.b.api.send(c, tok, req) })
		if err != nil {
			log.Printf("发信失败 user=%s from=%s to=%s: %v", s.us.user, s.from, rcpt, err)
			failed = append(failed, rcpt)
			lastErr = err
			continue
		}
		sent = append(sent, rcpt)
	}
	log.Printf("SMTP 提交 user=%s from=%s 成功=%v 失败=%v", s.us.user, s.from, sent, failed)
	if len(failed) == 0 {
		return nil
	}
	if len(sent) == 0 {
		return smtpErrFromAPI(lastErr)
	}
	// 部分成功：不能回临时失败（客户端重发会让已成功的收件人收到重复邮件），回永久失败并列出失败的收件人
	return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 5, 0},
		Message: fmt.Sprintf("Delivered to %s; failed for %s", strings.Join(sent, ","), strings.Join(failed, ","))}
}

func smtpErrFromAPI(err error) error {
	var ae *apiError
	if errors.As(err, &ae) {
		switch {
		case ae.Code == "DAILY_SEND_LIMIT":
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Daily sending limit reached"}
		case ae.Code == "SEND_NOT_ALLOWED" || ae.Code == "IMPERSONATION_READ_ONLY":
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sending not allowed for this mailbox"}
		case ae.Status == 429:
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Rate limited, try again later"}
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
