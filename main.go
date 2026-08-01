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

	"blitiri.com.ar/go/spf"
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

// 取邮箱地址的域名部分
func domainOf(addr string) string {
	addr = strings.Trim(addr, "<> ")
	i := strings.LastIndex(addr, "@")
	if i < 0 || i == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[i+1:])
}

// 取 RFC5322 From 头的域名。DMARC 判定的是这个域，
// 而不是信封发件人（MAIL FROM），两者可以不同。
func headerFromDomain(rawEmail []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(rawEmail))
	if err != nil {
		return ""
	}
	list, err := msg.Header.AddressList("From")
	if err != nil || len(list) == 0 {
		return ""
	}
	return domainOf(list[0].Address)
}

// DMARC 对齐检查。relaxed 模式下只要组织域一致即可，
// strict 模式要求完全相同。
// 注意：这里用「标签边界后缀匹配」近似组织域，没有引入公共后缀表(PSL)，
// 因此对 example.co.uk 这类多级后缀域名判定偏宽松。
func domainsAligned(authDomain, fromDomain string, strict bool) bool {
	if authDomain == "" || fromDomain == "" {
		return false
	}
	authDomain = strings.ToLower(strings.TrimSuffix(authDomain, "."))
	fromDomain = strings.ToLower(strings.TrimSuffix(fromDomain, "."))
	if authDomain == fromDomain {
		return true
	}
	if strict {
		return false
	}
	return strings.HasSuffix(authDomain, "."+fromDomain) ||
		strings.HasSuffix(fromDomain, "."+authDomain)
}

// 真实 SPF 判定：依赖发件方 IP、EHLO 域和信封发件人。
// 返回 (结果, 参与判定的域名)，域名供 DMARC 对齐使用。
func verifySPF(clientIP net.IP, helo, mailFrom string) (string, string) {
	sender := strings.Trim(mailFrom, "<> ")
	domain := domainOf(sender)

	// 空信封发件人（退信场景）按 RFC 7208 回落到 EHLO 域
	if domain == "" {
		domain = strings.ToLower(strings.TrimSuffix(helo, "."))
		if domain == "" {
			return "none", ""
		}
		sender = "postmaster@" + domain
	}

	if clientIP == nil {
		return "none", domain
	}

	res, _ := spf.CheckHostWithSender(clientIP, helo, sender)
	switch res {
	case spf.Pass:
		return "pass", domain
	case spf.Fail:
		return "fail", domain
	case spf.SoftFail:
		return "softfail", domain
	case spf.Neutral:
		return "neutral", domain
	case spf.TempError:
		return "temperror", domain
	case spf.PermError:
		return "permerror", domain
	default:
		return "none", domain
	}
}

// DKIM 校验，返回 (结果, 校验通过的签名域列表)
func verifyDKIM(rawEmail []byte) (string, []string) {
	verifications, err := dkim.Verify(bytes.NewReader(rawEmail))
	if err != nil {
		return "temperror", nil
	}
	if len(verifications) == 0 {
		return "none", nil
	}

	var passed []string
	for _, v := range verifications {
		if v.Err == nil {
			passed = append(passed, v.Domain)
		}
	}
	if len(passed) > 0 {
		return "pass", passed
	}
	return "fail", nil
}

// 查 DMARC 记录，沿父域回退一级（近似组织域）
func lookupDMARC(fromDomain string) *dmarc.Record {
	candidates := []string{fromDomain}
	if labels := strings.Split(fromDomain, "."); len(labels) > 2 {
		candidates = append(candidates, strings.Join(labels[1:], "."))
	}
	for _, d := range candidates {
		if rec, err := dmarc.Lookup(d); err == nil && rec != nil {
			return rec
		}
	}
	return nil
}

// 真实 DMARC 判定：要求 SPF 或 DKIM 至少一项 pass 且与 From 域对齐
func verifyDMARC(rawEmail []byte, spfResult, spfDomain, dkimResult string, dkimDomains []string) string {
	fromDomain := headerFromDomain(rawEmail)
	if fromDomain == "" {
		return "none"
	}

	rec := lookupDMARC(fromDomain)
	if rec == nil {
		// 没有发布 DMARC 记录，无策略可依
		return "none"
	}

	spfOK := spfResult == "pass" &&
		domainsAligned(spfDomain, fromDomain, rec.SPFAlignment == dmarc.AlignmentStrict)

	dkimOK := false
	if dkimResult == "pass" {
		for _, d := range dkimDomains {
			if domainsAligned(d, fromDomain, rec.DKIMAlignment == dmarc.AlignmentStrict) {
				dkimOK = true
				break
			}
		}
	}

	if spfOK || dkimOK {
		return "pass"
	}
	return "fail"
}

// ==========================================
// SMTP 服务实现
// ==========================================
type Backend struct{}

func (be *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &Session{}
	// 记录发件方 IP 与 HELO，SPF 判定必须依赖这两项
	if c != nil {
		if conn := c.Conn(); conn != nil {
			if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				s.ClientIP = addr.IP
			}
		}
		s.Helo = c.Hostname()
	}
	return s, nil
}

type Session struct {
	From     string
	To       string
	ClientIP net.IP
	Helo     string
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

	// 执行邮件验证（在转发前完成，此时发件方 IP 尚未丢失）
	spfResult, spfDomain := verifySPF(s.ClientIP, s.Helo, s.From)
	dkimResult, dkimDomains := verifyDKIM(rawEmail)
	dmarcResult := verifyDMARC(rawEmail, spfResult, spfDomain, dkimResult, dkimDomains)

	verification := EmailVerification{
		SPFResult:   spfResult,
		DKIMResult:  dkimResult,
		DMARCResult: dmarcResult,
	}
	verification.AuthResults = fmt.Sprintf(
		"%s; spf=%s smtp.mailfrom=%s; dkim=%s; dmarc=%s",
		DomainName, spfResult, spfDomain, dkimResult, dmarcResult,
	)
	log.Printf("验证结果: SPF=%s (ip=%v domain=%s), DKIM=%s %v, DMARC=%s",
		spfResult, s.ClientIP, spfDomain, dkimResult, dkimDomains, dmarcResult)

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

// 只清空信封，ClientIP/Helo 属于连接级信息，同一连接可投递多封邮件
func (s *Session) Reset() {
	s.From = ""
	s.To = ""
}
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
