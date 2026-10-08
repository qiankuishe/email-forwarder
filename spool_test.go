package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpoolAcceptsWhenAPIDownAndRedeliversLater(t *testing.T) {
	spoolDir = t.TempDir()
	os.MkdirAll(filepath.Join(spoolDir, "failed"), 0700)
	defer func() { spoolDir = "" }()

	var up atomic.Bool
	var delivered atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if !up.Load() {
			w.WriteHeader(503)
			return
		}
		if r.Header.Get("X-Email-Auth-Token") != "rotated-key" {
			w.WriteHeader(401)
			return
		}
		delivered.Add(1)
		w.WriteHeader(200)
	}))
	defer api.Close()
	setEndpoints(t, &Endpoint{WebhookURL: api.URL, AuthToken: "old-key"})
	addr := startTestSMTP(t)

	if err := sendTestMail(addr, []string{"x@example.com"}, testMsg); err != nil {
		t.Fatalf("开启缓冲后 API 故障时应回 250，实际 %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(spoolDir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("应有 1 封缓冲邮件，实际 %d", len(files))
	}

	// API 恢复，同时主项目轮换了密钥：重投应使用当前端点的新密钥
	up.Store(true)
	mu.Lock()
	endpoints[api.URL].AuthToken = "rotated-key"
	mu.Unlock()
	processSpoolOnce(time.Now()) // 未到退避时间，不应投递
	if delivered.Load() != 0 {
		t.Fatal("未到退避时间不应重投")
	}
	processSpoolOnce(time.Now().Add(2 * time.Minute))
	if delivered.Load() != 1 {
		t.Fatalf("应重投成功 1 次，实际 %d", delivered.Load())
	}
	files, _ = filepath.Glob(filepath.Join(spoolDir, "*"))
	if len(files) != 1 { // 只剩 failed/ 目录
		t.Errorf("投递成功后缓冲文件应删除，剩余 %v", files)
	}
}

func TestSpoolDisabledKeeps451(t *testing.T) {
	spoolDir = ""
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer api.Close()
	setEndpoints(t, &Endpoint{WebhookURL: api.URL, AuthToken: "k"})
	addr := startTestSMTP(t)
	if c := smtpCode(sendTestMail(addr, []string{"x@example.com"}, testMsg)); c != 451 {
		t.Errorf("默认（不开缓冲）应保持 451，实际 %d", c)
	}
}

func TestSpoolExpiredMovesToFailed(t *testing.T) {
	spoolDir = t.TempDir()
	os.MkdirAll(filepath.Join(spoolDir, "failed"), 0700)
	defer func() { spoolDir = "" }()
	if err := spoolMessage([]byte(testMsg), deliveryMeta{From: "a@b"}, []string{"x@example.com"}); err != nil {
		t.Fatal(err)
	}
	processSpoolOnce(time.Now().Add(spoolMaxAge + time.Hour))
	failed, _ := filepath.Glob(filepath.Join(spoolDir, "failed", "*"))
	if len(failed) != 2 {
		t.Errorf("超时邮件应移入 failed/（eml+json），实际 %v", failed)
	}
}
