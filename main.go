package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/emersion/go-smtp"
	"golang.org/x/crypto/acme/autocert"
)

// ==========================================
// 核心配置区
// ==========================================
const (
	// 固定的握手鉴权密钥
	AuthToken = "ceemail"

	// 绑定的网关域名，用于申请 TLS 证书
	DomainName = "mx.300031.xyz"

	// 本地持久化保存已注册收件端的文件名
	RegistryFile = "endpoints.json"
)

// 注册的收件端
type Endpoint struct {
	WebhookURL string    `json:"webhook_url"`
	LastSeen   time.Time `json:"last_seen"`
	IsHealthy  bool      `json:"is_healthy"`
}

var (
	endpoints = make(map[string]*Endpoint)
	mu        sync.RWMutex
)

// ==========================================
// 持久化与状态管理
// ==========================================
func loadEndpoints() {
	data, err := os.ReadFile(RegistryFile)
	if err == nil {
		var list []string
		if err := json.Unmarshal(data, &list); err == nil {
			mu.Lock()
			for _, url := range list {
				endpoints[url] = &Endpoint{
					WebhookURL: url,
					LastSeen:   time.Now(),
					IsHealthy:  false, // 启动时设为 false，等待探活
				}
			}
			mu.Unlock()
			log.Printf("已从文件加载 %d 个收件端", len(list))
		}
	}
}

func saveEndpoints() {
	mu.RLock()
	var list []string
	for url := range endpoints {
		list = append(list, url)
	}
	mu.RUnlock()

	data, _ := json.MarshalIndent(list, "", "  ")
	os.WriteFile(RegistryFile, data, 0644)
}

// ==========================================
// API 处理 (握手注册与状态展示)
// ==========================================

// 握手注册接口 (POST /register)
// Body JSON: {"webhook_url": "https://mail.amaeru.com/api/email/incoming"}
// Header: X-Email-Auth-Token: YOUR_SUPER_SECRET_TOKEN
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("X-Email-Auth-Token")
	if token != AuthToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		WebhookURL string `json:"webhook_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.WebhookURL == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	mu.Lock()
	if _, exists := endpoints[req.WebhookURL]; !exists {
		log.Printf("注册了新的收件端: %s", req.WebhookURL)
	}
	endpoints[req.WebhookURL] = &Endpoint{
		WebhookURL: req.WebhookURL,
		LastSeen:   time.Now(),
		IsHealthy:  true, // 刚注册认为存活
	}
	mu.Unlock()

	saveEndpoints()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "registered successfully"})
}

// 状态面板 (GET /)
func statusHandler(w http.ResponseWriter, r *http.Request) {
	// 如果不是根目录，返回 404，防止其他奇怪的请求
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	mu.RLock()
	healthyCount := 0
	totalCount := len(endpoints)
	for _, ep := range endpoints {
		if ep.IsHealthy {
			healthyCount++
		}
	}
	mu.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	if healthyCount > 0 {
		fmt.Fprintf(w, `
			<html>
			<head><title>SMTP Gateway Status</title></head>
			<body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
				<h1 style="color: green;">2: 连接成功</h1>
				<p>%d 个收件端正常工作中 (共注册 %d 个)</p>
			</body>
			</html>
		`, healthyCount, totalCount)
	} else {
		fmt.Fprintf(w, `
			<html>
			<head><title>SMTP Gateway Status</title></head>
			<body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
				<h1 style="color: red;">1: 未连接</h1>
				<p>当前没有健康的收件端 (共注册 %d 个)</p>
			</body>
			</html>
		`, totalCount)
	}
}

// ==========================================
// 探活机制 (后台轮询)
// ==========================================
func startHealthCheck() {
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		mu.RLock()
		var urls []string
		for url := range endpoints {
			urls = append(urls, url)
		}
		mu.RUnlock()

		for _, url := range urls {
			// 对 webhook 发送空 POST 或 GET 请求探活
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "Email-Gateway-HealthCheck")

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)

			mu.Lock()
			ep, exists := endpoints[url]
			if exists {
				if err != nil || resp.StatusCode >= 500 {
					ep.IsHealthy = false
				} else {
					ep.IsHealthy = true
					ep.LastSeen = time.Now()
				}
			}
			mu.Unlock()
			if resp != nil {
				resp.Body.Close()
			}
		}
	}
}

// ==========================================
// 邮件验证功能
// ==========================================
type EmailVerification struct {
	SPFResult   string
	DKIMResult  string
	DMARCResult string
	AuthResults string
}

// 验证 SPF
func verifySPF(from string, clientIP string) string {
	// 提取发件人域名
	parts := strings.Split(from, "@")
	if len(parts) != 2 {
		return "none"
	}
	domain := strings.Trim(parts[1], "<>")

	// 简化的 SPF 检查：查询 DNS TXT 记录
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return "none"
	}

	// 查找 SPF 记录
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			// 简单判断：包含 +all 或 ~all
			if strings.Contains(txt, "+all") {
				return "pass"
			} else if strings.Contains(txt, "~all") {
				return "softfail"
			} else if strings.Contains(txt, "-all") {
				return "fail"
			}
			return "neutral"
		}
	}
	return "none"
}

// 验证 DKIM
func verifyDKIM(rawEmail []byte) string {
	// 使用 go-msgauth 的 DKIM 验证
	verifications, err := dkim.Verify(bytes.NewReader(rawEmail))
	if err != nil || len(verifications) == 0 {
		return "none"
	}

	// 检查所有签名
	for _, v := range verifications {
		if v.Err == nil {
			return "pass"
		}
	}
	return "fail"
}

// 验证 DMARC
func verifyDMARC(from string) string {
	parts := strings.Split(from, "@")
	if len(parts) != 2 {
		return "none"
	}
	domain := strings.Trim(parts[1], "<>")

	// 查询 _dmarc.domain 的 TXT 记录
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		return "none"
	}

	// 查找 DMARC 记录
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			record, err := dmarc.Parse(txt)
			if err != nil {
				return "none"
			}
			// 如果有 DMARC 记录，根据策略返回结果
			if record.Policy == dmarc.PolicyNone {
				return "pass"
			}
			return "pass" // 有策略就算通过
		}
	}
	return "none"
}

// ==========================================
// SMTP 服务实现
// ==========================================
type Backend struct{}

func (be *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{}, nil
}

type Session struct {
	From string
	To   string
}

func (s *Session) AuthPlain(username, password string) error {
	return smtp.ErrAuthUnsupported
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.From = from
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.To = to
	return nil
}

func (s *Session) Data(r io.Reader) error {
	mu.RLock()
	var healthyURLs []string
	for url, ep := range endpoints {
		if ep.IsHealthy {
			healthyURLs = append(healthyURLs, url)
		}
	}
	mu.RUnlock()

	if len(healthyURLs) == 0 {
		log.Printf("拒绝接收邮件：无健康的收件端")
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Temporary local problem - no active backend",
		}
	}

	// 限制读取最大 26MB
	buf := new(bytes.Buffer)
	_, err := io.CopyN(buf, r, 26*1024*1024)
	if err != nil && err != io.EOF {
		return &smtp.SMTPError{Code: 452, Message: "Message too large"}
	}

	rawEmail := buf.Bytes()
	log.Printf("收到邮件: %s -> %s, 开始验证...", s.From, s.To)

	// 执行邮件验证
	verification := EmailVerification{
		SPFResult:  verifySPF(s.From, "unknown"), // 客户端IP在此处无法获取，可以后续优化
		DKIMResult: verifyDKIM(rawEmail),
		DMARCResult: verifyDMARC(s.From),
	}
	verification.AuthResults = fmt.Sprintf(
		"spf=%s; dkim=%s; dmarc=%s",
		verification.SPFResult,
		verification.DKIMResult,
		verification.DMARCResult,
	)
	log.Printf("验证结果: SPF=%s, DKIM=%s, DMARC=%s",
		verification.SPFResult, verification.DKIMResult, verification.DMARCResult)

	log.Printf("开始分发给 %d 个收件端...", len(healthyURLs))

	var wg sync.WaitGroup
	var muResult sync.Mutex
	anyAccepted := false
	allNotFound := true

	// 并发投递给所有存活的后端
	for _, url := range healthyURLs {
		wg.Add(1)
		go func(webhookURL string) {
			defer wg.Done()

			req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(rawEmail))
			if err != nil {
				return
			}
			req.Header.Set("X-Email-Auth-Token", AuthToken)
			req.Header.Set("X-Forwarded-From", s.From)
			req.Header.Set("X-Forwarded-To", s.To)
			req.Header.Set("Content-Type", "message/rfc822")

			// 添加验证结果头
			req.Header.Set("X-SPF-Result", verification.SPFResult)
			req.Header.Set("X-DKIM-Result", verification.DKIMResult)
			req.Header.Set("X-DMARC-Result", verification.DMARCResult)
			req.Header.Set("X-Auth-Results", verification.AuthResults)

			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[%s] 投递失败: %v", webhookURL, err)
				return
			}
			defer resp.Body.Close()

			muResult.Lock()
			defer muResult.Unlock()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				anyAccepted = true
				allNotFound = false
			} else if resp.StatusCode == 404 {
				// 后端明确表示找不到该用户，不视为严重错误，只是此后端不处理
			} else {
				// 其他 4xx/5xx 错误
				allNotFound = false
			}
		}(url)
	}

	wg.Wait()

	if anyAccepted {
		log.Printf("邮件成功投递。")
		return nil
	} else if allNotFound {
		// 所有存活的后端都返回 404，说明没有任何账号匹配，退信
		log.Printf("所有收件端均无此账号: %s", s.To)
		return &smtp.SMTPError{Code: 550, Message: "User unknown"}
	}

	// 投递过程中发生内部错误，让发件方重试
	log.Printf("邮件分发遭遇错误，要求发件方重试。")
	return &smtp.SMTPError{Code: 451, Message: "Backend processing error"}
}

func (s *Session) Reset() {}
func (s *Session) Logout() error {
	return nil
}

// ==========================================
// Main 启动
// ==========================================
func main() {
	loadEndpoints()
	go startHealthCheck()

	// 尝试加载手动配置的证书
	certFile := fmt.Sprintf("./certs/%s/%s", DomainName, DomainName)
	keyFile := fmt.Sprintf("./certs/%s/%s.key", DomainName, DomainName)

	var tlsConfig *tls.Config

	// 检查是否存在手动配置的证书
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			log.Printf("发现手动配置的证书文件，使用手动证书")
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				log.Fatalf("加载证书失败: %v", err)
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				ServerName:   DomainName,
			}
			log.Printf("手动证书加载成功")
		}
	}

	// 如果没有手动证书，使用 autocert
	var certManager *autocert.Manager
	if tlsConfig == nil {
		log.Printf("未找到手动证书，使用 Let's Encrypt 自动证书")
		certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(DomainName),
			Cache:      autocert.DirCache("./certs"),
		}
		tlsConfig = certManager.TLSConfig()
		tlsConfig.ServerName = DomainName
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", statusHandler)
	mux.HandleFunc("/register", registerHandler) // 供后端主动注册使用

	httpServer := &http.Server{
		Addr: ":8088",
	}

	// 如果使用 autocert，HTTP 服务器需要处理证书验证
	if certManager != nil {
		httpServer.Handler = certManager.HTTPHandler(mux)
	} else {
		httpServer.Handler = mux
	}

	go func() {
		log.Printf("启动 HTTP 状态/注册面板于 :8088")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP 服务失败: %v", err)
		}
	}()

	be := &Backend{}
	s := smtp.NewServer(be)

	s.Addr = ":25"
	s.Domain = DomainName
	s.ReadTimeout = 60 * time.Second
	s.WriteTimeout = 60 * time.Second
	s.MaxMessageBytes = 26 * 1024 * 1024
	s.MaxRecipients = 50
	s.AllowInsecureAuth = false

	s.TLSConfig = tlsConfig

	log.Printf("启动 SMTP 服务于 :25，域名: %s", DomainName)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("SMTP 服务失败: %v", err)
	}
}
