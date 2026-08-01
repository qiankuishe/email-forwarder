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
	// 注册接口的准入密钥（测试阶段暂不强制校验，见 registerHandler）。
	// 可通过环境变量 REGISTER_AUTH_TOKEN 覆盖。
	DefaultRegisterToken = "ceemail"

	// 绑定的网关域名，用于申请 TLS 证书
	DomainName = "mx.300031.xyz"

	// 本地持久化保存已注册收件端的文件名
	RegistryFile = "endpoints.json"

	// 收件端超过此时长未续约（未重新握手/未探活成功）则视为失效并清理
	EndpointTTL = 7 * 24 * time.Hour
)

// 注册接口的准入密钥，启动时从环境变量加载，兼容旧的硬编码默认值
var registerToken = DefaultRegisterToken

// 测试阶段默认不校验注册准入密钥，方便调试。
// 生产环境设置环境变量 REQUIRE_REGISTER_AUTH=true 开启校验。
var requireRegisterAuth = false

// 从环境变量加载配置，覆盖硬编码默认值
func loadConfigFromEnv() {
	if v := os.Getenv("REGISTER_AUTH_TOKEN"); v != "" {
		registerToken = v
	}
	if v := os.Getenv("REQUIRE_REGISTER_AUTH"); v == "true" || v == "1" {
		requireRegisterAuth = true
	}
	log.Printf("注册准入校验: %v（测试阶段可设 REQUIRE_REGISTER_AUTH=true 开启）", requireRegisterAuth)
}

// 注册的收件端。每个 webhook 拥有独立的转发密钥（由主项目在握手时传入），
// 转发邮件时使用这个密钥而不是网关自身的注册密钥，实现"每端点独立密钥"。
type Endpoint struct {
	WebhookURL string    `json:"webhook_url"`
	AuthToken  string    `json:"auth_token"` // 转发邮件时携带的 X-Email-Auth-Token
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
	if err != nil {
		return
	}

	// 新格式：完整 Endpoint 结构（含各自的 auth_token）
	var full map[string]*Endpoint
	if err := json.Unmarshal(data, &full); err == nil && len(full) > 0 {
		mu.Lock()
		for url, ep := range full {
			ep.WebhookURL = url
			ep.IsHealthy = false // 启动时设为 false，等待探活
			endpoints[url] = ep
		}
		mu.Unlock()
		log.Printf("已从文件加载 %d 个收件端", len(full))
		return
	}

	// 兼容旧格式：仅 URL 列表，没有独立密钥时回退到 registerToken
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		mu.Lock()
		for _, url := range list {
			endpoints[url] = &Endpoint{
				WebhookURL: url,
				AuthToken:  registerToken,
				LastSeen:   time.Now(),
				IsHealthy:  false,
			}
		}
		mu.Unlock()
		log.Printf("已从文件加载 %d 个收件端（旧格式，已回退到默认密钥）", len(list))
	}
}

func saveEndpoints() {
	mu.RLock()
	snapshot := make(map[string]*Endpoint, len(endpoints))
	for url, ep := range endpoints {
		epCopy := *ep
		snapshot[url] = &epCopy
	}
	mu.RUnlock()

	data, _ := json.MarshalIndent(snapshot, "", "  ")
	os.WriteFile(RegistryFile, data, 0644)
}

// 清理长期未续约的收件端，避免 endpoints.json 无限增长
func cleanupStaleEndpoints() {
	mu.Lock()
	removed := 0
	for url, ep := range endpoints {
		if time.Since(ep.LastSeen) > EndpointTTL {
			delete(endpoints, url)
			removed++
			log.Printf("清理长期失效的收件端: %s (超过 %s 未续约)", url, EndpointTTL)
		}
	}
	mu.Unlock()

	if removed > 0 {
		saveEndpoints()
	}
}

// ==========================================
// API 处理 (握手注册与状态展示)
// ==========================================

// 握手注册接口 (POST /register)
// Body JSON: {"webhook_url": "https://mail.example.com/api/email/incoming", "auth_token": "xxx"}
// Header: X-Email-Auth-Token: 注册准入密钥（测试阶段可不带，见下方说明）
//
// auth_token 是主项目自己生成、用于后续接收邮件时校验来源的密钥
// （对应主项目 EMAIL_WEBHOOK_SECRET / inbound_routers.secret_key）。
// 网关会把它和 webhook_url 绑定保存，转发邮件时使用这个密钥而不是
// 网关自身的注册准入密钥，从而让两端真正共享同一份密钥。
//
// 【测试阶段】REQUIRE_REGISTER_AUTH=false（默认）时不校验 X-Email-Auth-Token，
// 方便调试；生产环境应设置 REQUIRE_REGISTER_AUTH=true 并配置 REGISTER_AUTH_TOKEN。
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if requireRegisterAuth {
		token := r.Header.Get("X-Email-Auth-Token")
		if token != registerToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var req struct {
		WebhookURL string `json:"webhook_url"`
		AuthToken  string `json:"auth_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.WebhookURL == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// auth_token 未提供时回退到注册准入密钥，保持向后兼容
	authToken := req.AuthToken
	if authToken == "" {
		authToken = registerToken
	}

	mu.Lock()
	_, existed := endpoints[req.WebhookURL]
	endpoints[req.WebhookURL] = &Endpoint{
		WebhookURL: req.WebhookURL,
		AuthToken:  authToken,
		LastSeen:   time.Now(),
		IsHealthy:  true, // 刚注册/续约认为存活，等待下一轮探活确认
	}
	mu.Unlock()

	if existed {
		log.Printf("收件端重新握手（幂等更新密钥）: %s", req.WebhookURL)
	} else {
		log.Printf("注册了新的收件端: %s", req.WebhookURL)
	}

	saveEndpoints()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "registered successfully"})
}

// 注销接口 (POST /unregister)，供主项目主动下线某个 webhook 时调用，
// 避免只能被动等待 TTL 过期清理。
func unregisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if requireRegisterAuth {
		token := r.Header.Get("X-Email-Auth-Token")
		if token != registerToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var req struct {
		WebhookURL string `json:"webhook_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.WebhookURL == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	mu.Lock()
	_, existed := endpoints[req.WebhookURL]
	delete(endpoints, req.WebhookURL)
	mu.Unlock()

	if existed {
		saveEndpoints()
		log.Printf("收件端已注销: %s", req.WebhookURL)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"removed": existed})
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
//
// 说明：GET 请求探测 webhook 无法反映真实可用性——主项目 /api/email/incoming
// 只注册了 POST handler，GET 会被路由框架直接 404，而 404 在旧逻辑里被当作"健康"，
// 因此鉴权失败(401/403)、方法不允许(404/405)等情况全部被误判为健康。
//
// 改为发送一个空的 POST 请求（不带 Content-Length 邮件体），并携带该端点自己的
// auth_token。真实的收信端点在这种请求下预期返回 400（邮件内容为空）而不是
// 401/403/404/5xx，说明鉴权和路由都是通的；返回 401/403 说明密钥不匹配；
// 5xx 或网络错误才视为不健康。
func probeEndpoint(ep *Endpoint) bool {
	req, err := http.NewRequest("POST", ep.WebhookURL, bytes.NewReader(nil))
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Email-Gateway-HealthCheck")
	req.Header.Set("X-Email-Auth-Token", ep.AuthToken)
	req.Header.Set("X-Health-Check", "1")
	req.Header.Set("Content-Type", "message/rfc822")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 5xx 说明后端本身出问题；401/403 说明密钥不匹配但服务是活的——
	// 这里仍标记为不健康，因为密钥不对邮件也投不进去，暴露出来能及时发现配置错误。
	if resp.StatusCode >= 500 {
		return false
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		log.Printf("[%s] 健康检查发现鉴权失败（密钥可能不一致），标记为不健康", ep.WebhookURL)
		return false
	}
	return true
}

func startHealthCheck() {
	ticker := time.NewTicker(15 * time.Second)
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ticker.C:
			mu.RLock()
			snapshot := make([]*Endpoint, 0, len(endpoints))
			for _, ep := range endpoints {
				epCopy := *ep
				snapshot = append(snapshot, &epCopy)
			}
			mu.RUnlock()

			for _, ep := range snapshot {
				healthy := probeEndpoint(ep)

				mu.Lock()
				if cur, exists := endpoints[ep.WebhookURL]; exists {
					cur.IsHealthy = healthy
					if healthy {
						cur.LastSeen = time.Now()
					}
				}
				mu.Unlock()
			}
		case <-cleanupTicker.C:
			cleanupStaleEndpoints()
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
	To       []string // 一封邮件可能有多个 RCPT TO，必须全部收集，否则会丢信
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
	// 追加而非覆盖：同一封邮件可能同时投给多个收件人（RCPT TO 多次），
	// 之前的实现直接赋值会丢掉除最后一个之外的所有收件人。
	for _, existing := range s.To {
		if existing == to {
			return nil // 去重，避免重复 RCPT TO 导致重复转发
		}
	}
	s.To = append(s.To, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	mu.RLock()
	var healthyEndpoints []Endpoint
	for _, ep := range endpoints {
		if ep.IsHealthy {
			healthyEndpoints = append(healthyEndpoints, *ep)
		}
	}
	mu.RUnlock()

	if len(healthyEndpoints) == 0 {
		log.Printf("拒绝接收邮件：无健康的收件端")
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Temporary local problem - no active backend",
		}
	}

	if len(s.To) == 0 {
		log.Printf("拒绝接收邮件：没有收件人")
		return &smtp.SMTPError{Code: 554, Message: "No valid recipients"}
	}

	// 限制读取最大 26MB
	buf := new(bytes.Buffer)
	_, err := io.CopyN(buf, r, 26*1024*1024)
	if err != nil && err != io.EOF {
		return &smtp.SMTPError{Code: 452, Message: "Message too large"}
	}

	rawEmail := buf.Bytes()
	log.Printf("收到邮件: %s -> %v, 开始验证...", s.From, s.To)

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

	log.Printf("开始分发给 %d 个收件端 x %d 个收件人...", len(healthyEndpoints), len(s.To))

	type deliveryResult struct {
		accepted bool
		notFound bool
	}

	var wg sync.WaitGroup
	var muResult sync.Mutex
	// 按收件人记录投递结果，一个收件人的失败不应影响其他收件人的判定
	results := make(map[string]*deliveryResult, len(s.To))
	for _, to := range s.To {
		results[to] = &deliveryResult{notFound: true}
	}

	// 对每个收件人 x 每个健康端点分别投递，
	// 避免像旧实现那样把多个 RCPT TO 压缩成一个 X-Forwarded-To 而丢信。
	for _, to := range s.To {
		for _, ep := range healthyEndpoints {
			wg.Add(1)
			go func(webhookURL, authToken, rcptTo string) {
				defer wg.Done()

				req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(rawEmail))
				if err != nil {
					return
				}
				req.Header.Set("X-Email-Auth-Token", authToken)
				req.Header.Set("X-Forwarded-From", s.From)
				req.Header.Set("X-Forwarded-To", rcptTo)
				req.Header.Set("Content-Type", "message/rfc822")

				// 添加验证结果头
				req.Header.Set("X-SPF-Result", verification.SPFResult)
				req.Header.Set("X-DKIM-Result", verification.DKIMResult)
				req.Header.Set("X-DMARC-Result", verification.DMARCResult)
				req.Header.Set("X-Auth-Results", verification.AuthResults)

				client := &http.Client{Timeout: 30 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					log.Printf("[%s] 投递给 %s 失败: %v", webhookURL, rcptTo, err)
					muResult.Lock()
					results[rcptTo].notFound = false // 网络错误不等于"无此账号"，需要重试
					muResult.Unlock()
					return
				}
				defer resp.Body.Close()

				muResult.Lock()
				defer muResult.Unlock()

				res := results[rcptTo]
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					res.accepted = true
					res.notFound = false
				} else if resp.StatusCode == 404 {
					// 该后端明确表示找不到该收件人，保留 notFound，交给其他后端判断
				} else {
					// 其他 4xx/5xx 错误，不算"无此账号"
					res.notFound = false
				}
			}(ep.WebhookURL, ep.AuthToken, to)
		}
	}

	wg.Wait()

	// 逐个收件人判定投递结果，只要有一个收件人成功即可返回成功，
	// 让 SMTP 客户端认为整体投递成功（细粒度的按收件人拒绝会更复杂，
	// 目前场景下同一域名的收件人通常落在同一批后端，先满足"不丢信"）。
	anyAccepted := false
	allNotFound := true
	for _, res := range results {
		if res.accepted {
			anyAccepted = true
			allNotFound = false
		} else if !res.notFound {
			allNotFound = false
		}
	}

	if anyAccepted {
		log.Printf("邮件成功投递。")
		return nil
	} else if allNotFound {
		log.Printf("所有收件端均无匹配账号: %v", s.To)
		return &smtp.SMTPError{Code: 550, Message: "User unknown"}
	}

	log.Printf("邮件分发遭遇错误，要求发件方重试。")
	return &smtp.SMTPError{Code: 451, Message: "Backend processing error"}
}

// 只清空信封，ClientIP/Helo 属于连接级信息，同一连接可投递多封邮件
func (s *Session) Reset() {
	s.From = ""
	s.To = nil
}
func (s *Session) Logout() error {
	return nil
}

// ==========================================
// Main 启动
// ==========================================
func main() {
	loadConfigFromEnv()
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
	mux.HandleFunc("/register", registerHandler)     // 供后端主动注册/续约使用
	mux.HandleFunc("/unregister", unregisterHandler)  // 供后端主动下线 webhook 使用

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
