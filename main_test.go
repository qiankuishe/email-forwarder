package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// probeEndpoint 的判定口径是收件链路能否真正投递的唯一自动化信号，
// 判错会导致"面板显示正常但邮件全丢"，因此逐个状态码固定住行为。
func TestProbeEndpointHealthJudgement(t *testing.T) {
	cases := []struct {
		name        string
		statusCode  int
		wantHealthy bool
	}{
		{
			name:        "400 空邮件体是真实收件端的预期响应，鉴权与路由都通",
			statusCode:  http.StatusBadRequest,
			wantHealthy: true,
		},
		{
			name:        "200 也接受",
			statusCode:  http.StatusOK,
			wantHealthy: true,
		},
		{
			name:        "401 密钥不匹配，邮件投不进去",
			statusCode:  http.StatusUnauthorized,
			wantHealthy: false,
		},
		{
			name:        "403 同上",
			statusCode:  http.StatusForbidden,
			wantHealthy: false,
		},
		{
			name:        "404 该地址上没有收信端点",
			statusCode:  http.StatusNotFound,
			wantHealthy: false,
		},
		{
			name:        "405 典型于 webhook_url 误填成静态前端站点",
			statusCode:  http.StatusMethodNotAllowed,
			wantHealthy: false,
		},
		{
			name:        "500 后端故障",
			statusCode:  http.StatusInternalServerError,
			wantHealthy: false,
		},
		{
			name:        "502 后端故障",
			statusCode:  http.StatusBadGateway,
			wantHealthy: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("探活应使用 POST，实际为 %s", r.Method)
				}
				if got := r.Header.Get("X-Email-Auth-Token"); got != "test-token" {
					t.Errorf("探活未携带端点自己的密钥，得到 %q", got)
				}
				if got := r.Header.Get("X-Health-Check"); got != "1" {
					t.Errorf("探活缺少 X-Health-Check 头，得到 %q", got)
				}
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			ep := &Endpoint{WebhookURL: srv.URL, AuthToken: "test-token"}
			if got := probeEndpoint(ep); got != tc.wantHealthy {
				t.Errorf("状态码 %d：期望 healthy=%v，实际 %v", tc.statusCode, tc.wantHealthy, got)
			}
		})
	}
}

// 网络不可达必须判为不健康，否则邮件会被投向一个连不上的地址。
func TestProbeEndpointUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // 立刻关掉，制造连接失败

	ep := &Endpoint{WebhookURL: url, AuthToken: "test-token"}
	if probeEndpoint(ep) {
		t.Error("连接失败时应判为不健康")
	}
}
