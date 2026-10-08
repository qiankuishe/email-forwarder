// mail-proxy：让 iPhone「邮件」、Thunderbird、Outlook 等客户端通过 IMAP/SMTP 收发主项目邮件的薄代理。
//
// 完全无状态：不落盘、不存邮件、不存用户数据；除了「当前连接」的内存会话外什么都不保留。
// 所有读写都转成对主项目（Cloudflare Workers）现有 HTTP API 的调用，业务规则全部留在主 API。
// 换 VPS 时只需要同一份 .env + 证书，`docker compose --profile proxy up -d` 即可重建。
package main

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-smtp"
)

func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

// envAddr：监听地址。显式设为空或 off 表示不启用该端口。
func envAddr(name, def string) string {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	v = strings.TrimSpace(v)
	if strings.EqualFold(v, "off") || strings.EqualFold(v, "none") {
		return ""
	}
	return v
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil && v >= 0 {
		return v
	}
	return def
}

func envBool(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

type options struct {
	apiBase, apiOrigin      string
	authMode, appLoginPath  string
	hostname                string
	certFile, keyFile       string
	imapsAddr, imapAddr     string
	smtpsAddr, submitAddr   string
	allowInsecureAuth       bool
	maxConns, maxConnsPerIP int
	loginMaxFails           int
	loginWindow             time.Duration
	maxMessageBytes         int64
	maxRcpts                int
	proxy                   proxyConfig
}

func loadOptions() *options {
	o := &options{
		apiBase:           env("API_BASE_URL", ""),
		apiOrigin:         env("API_ORIGIN", ""),
		authMode:          env("AUTH_MODE", "login"),
		appLoginPath:      env("APP_LOGIN_PATH", "/api/auth/app-password/login"),
		hostname:          env("PROXY_HOSTNAME", "localhost"),
		certFile:          env("TLS_CERT_FILE", ""),
		keyFile:           env("TLS_KEY_FILE", ""),
		imapsAddr:         envAddr("IMAPS_ADDR", ":993"),
		imapAddr:          envAddr("IMAP_ADDR", ""), // 143 + STARTTLS，默认关闭
		smtpsAddr:         envAddr("SMTPS_ADDR", ":465"),
		submitAddr:        envAddr("SUBMISSION_ADDR", ":587"),
		allowInsecureAuth: envBool("ALLOW_INSECURE_AUTH", false), // 仅供本地测试：允许无 TLS 明文登录
		maxConns:          envInt("MAX_CONNECTIONS", 500),
		maxConnsPerIP:     envInt("MAX_CONNECTIONS_PER_IP", 20),
		loginMaxFails:     envInt("LOGIN_MAX_FAILS", 5),
		loginWindow:       time.Duration(envInt("LOGIN_FAIL_WINDOW_MINUTES", 15)) * time.Minute,
		maxMessageBytes:   int64(envInt("MAX_MESSAGE_BYTES", 25<<20)),
		maxRcpts:          envInt("MAX_RECIPIENTS", 20),
		proxy: proxyConfig{
			maxMessages:  envInt("MAX_MESSAGES_PER_FOLDER", 500),
			pollInterval: time.Duration(envInt("IDLE_POLL_SECONDS", 60)) * time.Second,
			rawCacheMax:  int64(envInt("RAW_CACHE_BYTES_PER_CONN", 32<<20)),
			maxRawBytes:  int64(envInt("MAX_MESSAGE_BYTES", 25<<20)) + 1<<20,
			accountDirs:  envBool("ACCOUNT_FOLDERS", true),
		},
	}
	if o.proxy.pollInterval < 10*time.Second {
		o.proxy.pollInterval = 10 * time.Second
	}
	return o
}

func main() {
	o := loadOptions()
	if o.apiBase == "" {
		log.Fatal("必须设置 API_BASE_URL（主项目 API 地址，如 https://api.example.com）")
	}
	if !strings.HasPrefix(o.apiBase, "https://") && !o.allowInsecureAuth {
		log.Fatal("API_BASE_URL 必须是 https://（用户密码会经它转发）")
	}
	if o.apiOrigin == "" {
		log.Printf("⚠️ 未设置 API_ORIGIN：主 API 生产环境的 CSRF 检查会拒绝没有 Origin 的写请求（标记已读、删除、发信），" +
			"请设为主 API FRONTEND_URL 白名单中的一个前端地址")
	}

	var tlsConfig *tls.Config
	if o.certFile != "" && o.keyFile != "" {
		r, err := newCertReloader(o.certFile, o.keyFile)
		if err != nil {
			log.Fatalf("加载证书失败: %v", err)
		}
		tlsConfig = &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12}
	} else if !o.allowInsecureAuth {
		log.Fatal("必须设置 TLS_CERT_FILE / TLS_KEY_FILE（IMAP/SMTP 会传输用户密码）")
	}

	api := newAPIClient(o.apiBase, o.apiOrigin, o.authMode, o.appLoginPath)
	limiter := newLoginLimiter(o.loginMaxFails, o.loginWindow)
	counter := newConnCounter(o.maxConns, o.maxConnsPerIP)

	var wg sync.WaitGroup
	start := func(name, addr string, implicitTLS bool, serve func(net.Listener) error) {
		if addr == "" {
			return
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("%s 监听 %s 失败: %v", name, addr, err)
		}
		// 先计数再套 TLS：服务器要能把连接识别为 *tls.Conn，否则会拒绝明文以外的登录判断
		ln = counter.wrap(ln)
		if implicitTLS {
			if tlsConfig == nil {
				log.Printf("%s 需要证书，未配置，跳过 %s", name, addr)
				ln.Close()
				return
			}
			ln = tls.NewListener(ln, tlsConfig)
		}
		log.Printf("%s 监听 %s", name, addr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serve(ln); err != nil {
				log.Printf("%s 退出: %v", name, err)
			}
		}()
	}

	newIMAP := func(starttls bool) *imapserver.Server {
		caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIdle: {}, imap.CapMove: {}, imap.CapSpecialUse: {}}
		opts := &imapserver.Options{
			NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
				return newIMAPSession(&o.proxy, api, limiter, c), nil, nil
			},
			Caps:         caps,
			InsecureAuth: o.allowInsecureAuth,
			Logger:       log.Default(),
		}
		if starttls {
			opts.TLSConfig = tlsConfig
		}
		return imapserver.New(opts)
	}
	newSMTP := func(starttls bool) *smtp.Server {
		s := smtp.NewServer(&submissionBackend{cfg: &o.proxy, api: api, limiter: limiter, maxRcpts: o.maxRcpts})
		s.Domain = o.hostname
		s.MaxMessageBytes = o.maxMessageBytes
		s.MaxRecipients = o.maxRcpts
		s.ReadTimeout = 2 * time.Minute
		s.WriteTimeout = 2 * time.Minute
		s.AllowInsecureAuth = o.allowInsecureAuth
		if starttls {
			s.TLSConfig = tlsConfig
		}
		return s
	}

	start("IMAPS", o.imapsAddr, true, newIMAP(false).Serve)
	start("IMAP(STARTTLS)", o.imapAddr, false, newIMAP(true).Serve)
	start("SMTPS", o.smtpsAddr, true, newSMTP(false).Serve)
	start("Submission(STARTTLS)", o.submitAddr, false, newSMTP(true).Serve)
	wg.Wait()
}

// ---------- 连接数限制 ----------

type connCounter struct {
	mu            sync.Mutex
	max, maxPerIP int
	total         int
	perIP         map[string]int
}

func newConnCounter(max, perIP int) *connCounter {
	return &connCounter{max: max, maxPerIP: perIP, perIP: map[string]int{}}
}

func (c *connCounter) wrap(l net.Listener) net.Listener { return &countedListener{Listener: l, c: c} }

type countedListener struct {
	net.Listener
	c *connCounter
}

func (l *countedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		l.c.mu.Lock()
		over := (l.c.max > 0 && l.c.total >= l.c.max) || (l.c.maxPerIP > 0 && l.c.perIP[host] >= l.c.maxPerIP)
		if !over {
			l.c.total++
			l.c.perIP[host]++
		}
		l.c.mu.Unlock()
		if over {
			log.Printf("连接数超限，拒绝 %s", host)
			conn.Close()
			continue
		}
		return &countedConn{Conn: conn, release: func() {
			l.c.mu.Lock()
			l.c.total--
			if l.c.perIP[host]--; l.c.perIP[host] <= 0 {
				delete(l.c.perIP, host)
			}
			l.c.mu.Unlock()
		}}, nil
	}
}

type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// ---------- 证书热加载（acme.sh 续期覆盖文件后自动生效） ----------

type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	mod               time.Time
	checked           time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	return r, r.load()
}

func (r *certReloader) load() error {
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	st, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	r.cert, r.mod = &c, st.ModTime()
	return nil
}

func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) > 30*time.Second {
		r.checked = time.Now()
		if st, err := os.Stat(r.certFile); err == nil && !st.ModTime().Equal(r.mod) {
			if err := r.load(); err != nil {
				log.Printf("⚠️ 新证书加载失败，继续使用旧证书: %v", err)
			}
		}
	}
	return r.cert, nil
}
