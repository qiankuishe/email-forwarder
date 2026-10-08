package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// httptest 服务器都在 127.0.0.1 上，测试里默认放开内网拦截；
// 需要验证拦截行为的用例自己临时关掉。
func TestMain(m *testing.M) {
	allowPrivateWebhooks = true
	dir, _ := os.MkdirTemp("", "gw-test")
	registryFile = filepath.Join(dir, "endpoints.json")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func withRegisterAuth(t *testing.T, require bool, token, prev string) {
	t.Helper()
	oldReq, oldTok, oldPrev := requireRegisterAuth, registerToken, registerTokenPrevious
	requireRegisterAuth, registerToken, registerTokenPrevious = require, token, prev
	t.Cleanup(func() { requireRegisterAuth, registerToken, registerTokenPrevious = oldReq, oldTok, oldPrev })
}

func TestRegisterRequiresTokenAndAcceptsPrevious(t *testing.T) {
	withRegisterAuth(t, true, "new-secret", "old-secret")
	body := `{"webhook_url":"https://api.example.com/api/email/incoming","auth_token":"k"}`
	cases := []struct {
		header string
		want   int
	}{
		{"", 401},
		{"wrong", 401},
		{"new-secret", 200},
		{"old-secret", 200},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
		if c.header != "" {
			req.Header.Set("X-Email-Auth-Token", c.header)
		}
		rec := httptest.NewRecorder()
		registerHandler(rec, req)
		if rec.Code != c.want {
			t.Errorf("token %q: 期望 %d，实际 %d", c.header, c.want, rec.Code)
		}
	}
	mu.Lock()
	delete(endpoints, "https://api.example.com/api/email/incoming")
	mu.Unlock()
}

func TestRegisterRejectsBadWebhookURL(t *testing.T) {
	withRegisterAuth(t, false, "x", "")
	allowPrivateWebhooks = false
	defer func() { allowPrivateWebhooks = true }()
	for _, u := range []string{
		"ftp://example.com/x",
		"file:///etc/passwd",
		"http://127.0.0.1:8080/x",
		"http://localhost/x",
		"http://169.254.169.254/latest/meta-data",
		"http://10.0.0.5/x",
		"https://user:pw@example.com/x",
	} {
		req := httptest.NewRequest("POST", "/register", strings.NewReader(`{"webhook_url":"`+u+`"}`))
		rec := httptest.NewRecorder()
		registerHandler(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s 应被拒绝，实际 %d", u, rec.Code)
		}
	}
}

func TestSafeControlBlocksPrivateAtDialTime(t *testing.T) {
	allowPrivateWebhooks = false
	defer func() { allowPrivateWebhooks = true }()
	if err := safeControl("tcp", "127.0.0.1:80", nil); err == nil {
		t.Error("应拦截回环地址")
	}
	if err := safeControl("tcp", "[::1]:80", nil); err == nil {
		t.Error("应拦截 IPv6 回环地址")
	}
	if err := safeControl("tcp", "100.64.1.1:80", nil); err == nil {
		t.Error("应拦截 CGNAT 地址")
	}
	if err := safeControl("tcp", net.JoinHostPort("1.1.1.1", "443"), nil); err != nil {
		t.Errorf("公网地址不应被拦截: %v", err)
	}
}

func TestSaveEndpointsUsesPrivatePermissions(t *testing.T) {
	mu.Lock()
	endpoints["https://perm.example.com/x"] = &Endpoint{WebhookURL: "https://perm.example.com/x", AuthToken: "t"}
	mu.Unlock()
	defer func() {
		mu.Lock()
		delete(endpoints, "https://perm.example.com/x")
		mu.Unlock()
	}()
	saveEndpoints()
	st, err := os.Stat(registryFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Errorf("endpoints.json 含投递密钥，权限应为 0600，实际 %v", st.Mode().Perm())
	}
}
