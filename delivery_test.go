package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

const testMsg = "From: a@example.org\r\nTo: x@example.com\r\nSubject: hi\r\nMessage-ID: <1@example.org>\r\n\r\nbody\r\n"

// 启动一个只监听 127.0.0.1 的网关 SMTP 实例
func startTestSMTP(t *testing.T) string {
	t.Helper()
	s := smtp.NewServer(&Backend{})
	s.Domain = "mx.test"
	s.MaxMessageBytes = maxMessageBytes
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	t.Cleanup(func() { s.Close() })
	return l.Addr().String()
}

func setEndpoints(t *testing.T, eps ...*Endpoint) {
	t.Helper()
	mu.Lock()
	old := endpoints
	endpoints = make(map[string]*Endpoint)
	for _, ep := range eps {
		ep.IsHealthy = true
		ep.LastSeen = time.Now()
		endpoints[ep.WebhookURL] = ep
	}
	mu.Unlock()
	t.Cleanup(func() { mu.Lock(); endpoints = old; mu.Unlock() })
}

// 明文 SMTP 投递（smtp.SendMail 强制 STARTTLS，测试里没有证书）
func sendTestMail(addr string, rcpts []string, msg string) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("sender.test"); err != nil {
		return err
	}
	if err := c.Mail("a@example.org", nil); err != nil {
		return err
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, msg); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func smtpCode(err error) int {
	if e, ok := err.(*smtp.SMTPError); ok {
		return e.Code
	}
	return 0
}

func TestDeliveryStatusMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   int // 0 = 成功
	}{
		{"2xx 成功", 200, `{}`, 0},
		{"404 无此邮箱 → 550", 404, `{"permanent":true}`, 550},
		{"410 邮箱过期 → 550", 410, `{"permanent":true}`, 550},
		{"413 过大 → 552（旧实现是 451 无限重投）", 413, `{"permanent":true}`, 552},
		{"400 permanent → 554", 400, `{"permanent":true}`, 554},
		{"400 不带 permanent → 451", 400, `{}`, 451},
		{"401 密钥不对 → 451", 401, `{}`, 451},
		{"429 → 451", 429, `{}`, 451},
		{"503 → 451", 503, `{"retryable":true}`, 451},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(c.status)
				w.Write([]byte(c.body))
			}))
			defer api.Close()
			setEndpoints(t, &Endpoint{WebhookURL: api.URL, AuthToken: "k"})
			addr := startTestSMTP(t)
			err := sendTestMail(addr, []string{"x@example.com"}, testMsg)
			if got := smtpCode(err); got != c.want {
				t.Errorf("期望 SMTP %d，实际 %d (%v)", c.want, got, err)
			}
		})
	}
}

// 旧实现：一个收件人成功、另一个临时失败时回 250，临时失败的那个直接丢信
func TestPartialTransientFailureIsRetried(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.Header.Get("X-Forwarded-To") == "ok@example.com" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(503)
	}))
	defer api.Close()
	setEndpoints(t, &Endpoint{WebhookURL: api.URL, AuthToken: "k"})
	addr := startTestSMTP(t)
	err := sendTestMail(addr, []string{"ok@example.com", "busy@example.com"}, testMsg)
	if smtpCode(err) != 451 {
		t.Fatalf("有收件人临时失败时应回 451 让发件方重投，实际 %v", err)
	}
}

func TestEveryRecipientDeliveredWithHeaders(t *testing.T) {
	var mu2 sync.Mutex
	got := map[string]string{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu2.Lock()
		got[r.Header.Get("X-Forwarded-To")] = r.Header.Get("X-Email-Auth-Token") + "|" + r.Header.Get("X-Gateway-Client-IP") + "|" + string(b)
		mu2.Unlock()
		w.WriteHeader(200)
	}))
	defer api.Close()
	setEndpoints(t, &Endpoint{WebhookURL: api.URL, AuthToken: "per-endpoint-key"})
	addr := startTestSMTP(t)
	if err := sendTestMail(addr, []string{"a@example.com", "b@example.com"}, testMsg); err != nil {
		t.Fatal(err)
	}
	for _, rc := range []string{"a@example.com", "b@example.com"} {
		v, ok := got[rc]
		if !ok {
			t.Fatalf("收件人 %s 未投递", rc)
		}
		parts := strings.SplitN(v, "|", 3)
		if parts[0] != "per-endpoint-key" || parts[1] != "127.0.0.1" || !strings.Contains(parts[2], "Subject: hi") {
			t.Errorf("投递内容不对: %q", v)
		}
	}
}

func TestOversizeMessageIsPermanent(t *testing.T) {
	old := maxMessageBytes
	maxMessageBytes = 1024
	defer func() { maxMessageBytes = old }()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer api.Close()
	setEndpoints(t, &Endpoint{WebhookURL: api.URL, AuthToken: "k"})
	addr := startTestSMTP(t)
	big := testMsg + strings.Repeat(strings.Repeat("x", 70)+"\r\n", 60)
	if c := smtpCode(sendTestMail(addr, []string{"x@example.com"}, big)); c != 552 {
		t.Errorf("超限应回 552，实际 %d", c)
	}
}

func TestPerIPConnectionLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := smtp.NewServer(&Backend{})
	s.Domain = "mx.test"
	go s.Serve(newLimitedListener(ln, 100, 2))
	defer s.Close()

	var held []*smtp.Client
	for i := 0; i < 2; i++ {
		c, err := smtp.Dial(ln.Addr().String())
		if err == nil {
			err = c.Hello("x.test")
		}
		if err != nil {
			t.Fatalf("前两个连接应成功: %v", err)
		}
		held = append(held, c)
	}
	third, err := smtp.Dial(ln.Addr().String())
	if err == nil {
		err = third.Hello("x.test") // 客户端在首个命令时才读取问候语
		third.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "421") {
		t.Errorf("第三个连接应收到 421，实际 %v", err)
	}
	held[0].Close()
	time.Sleep(50 * time.Millisecond)
	c, err := smtp.Dial(ln.Addr().String())
	if err == nil {
		err = c.Hello("x.test")
	}
	if err != nil {
		t.Errorf("释放后应能再连: %v", err)
	} else {
		c.Close()
	}
	held[1].Close()
}
