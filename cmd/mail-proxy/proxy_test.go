package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// ---------- 模拟主 API（只实现代理用到的接口，行为对齐 api/src/routes） ----------

type mockEmail struct {
	id              uint32
	account         string
	subject, sender string
	unread, starred bool
	deleted, noRaw  bool
	received        time.Time
}

type mockAPI struct {
	mu       sync.Mutex
	emails   map[uint32]*mockEmail
	sent     []map[string]any
	uploads  int
	logins   int
	calls    []string
	origin   string
	nextID   uint32
	tokens   map[string]bool // 有效令牌
	readOnly map[string]bool
}

func newMockAPI() *mockAPI {
	m := &mockAPI{emails: map[uint32]*mockEmail{}, origin: "https://mail.test", nextID: 100,
		tokens: map[string]bool{}, readOnly: map[string]bool{}}
	base := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	m.emails[11] = &mockEmail{id: 11, account: "acc1", subject: "Hello one", sender: "alice@example.org", unread: true, received: base}
	m.emails[12] = &mockEmail{id: 12, account: "acc1", subject: "Second", sender: "bob@example.org", received: base.Add(time.Hour)}
	m.emails[13] = &mockEmail{id: 13, account: "acc1", subject: "Old no raw", sender: "carol@example.org", noRaw: true, received: base.Add(2 * time.Hour)}
	m.emails[14] = &mockEmail{id: 14, account: "acc1", subject: "Already deleted", sender: "dan@example.org", deleted: true, received: base.Add(3 * time.Hour)}
	return m
}

func (m *mockAPI) rawFor(e *mockEmail) string {
	return fmt.Sprintf("From: %s\r\nTo: me@300031.xyz\r\nSubject: %s\r\nMessage-ID: <m%d@example.org>\r\nDate: Thu, 01 Oct 2026 08:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody of %d\r\n",
		e.sender, e.subject, e.id, e.id)
}

func (m *mockAPI) add(subject string) uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	m.emails[m.nextID] = &mockEmail{id: m.nextID, account: "acc1", subject: subject, sender: "new@example.org", unread: true, received: time.Now()}
	return m.nextID
}

func jsonResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (m *mockAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, r.Method+" "+r.URL.Path)
	p := r.URL.Path

	// 生产环境的 CSRF：写请求必须带白名单内的 Origin
	if r.Method != http.MethodGet && r.Header.Get("Origin") != m.origin {
		jsonResp(w, 403, map[string]string{"error": "csrf", "code": "CSRF_NO_ORIGIN"})
		return
	}
	if p == "/api/auth/login" {
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		if b["email"] == "user@example.com" && b["password"] == "pw" || b["email"] == "admin-view@example.com" && b["password"] == "pw" {
			m.logins++
			tok := fmt.Sprintf("tok-%d", m.logins)
			// 与真实 API 一致：登录会删除该用户的其他会话
			for k := range m.tokens {
				delete(m.tokens, k)
			}
			m.tokens[tok] = true
			if strings.HasPrefix(b["email"], "admin-view") {
				m.readOnly[tok] = true
			}
			jsonResp(w, 200, map[string]any{"sessionToken": tok})
			return
		}
		jsonResp(w, 401, map[string]string{"error": "邮箱或密码错误"})
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !m.tokens[tok] {
		jsonResp(w, 401, map[string]string{"error": "无效的会话"})
		return
	}
	if m.readOnly[tok] && r.Method != http.MethodGet {
		jsonResp(w, 403, map[string]string{"error": "只读", "code": "IMPERSONATION_READ_ONLY"})
		return
	}
	switch {
	case p == "/api/auth/me":
		var imp any
		if m.readOnly[tok] {
			imp = map[string]string{"id": "admin"}
		}
		jsonResp(w, 200, map[string]any{"user": map[string]string{"id": "u1"}, "impersonatedBy": imp})
	case p == "/api/email/accounts":
		jsonResp(w, 200, map[string]any{"accounts": []map[string]any{{"id": "acc1", "name": "me@300031.xyz", "type": "permanent"}}})
	case p == "/api/email/emails" || p == "/api/email/accounts/acc1/emails":
		m.list(w, r)
	case p == "/api/email/accounts/acc1/sent-emails":
		var out []map[string]any
		for i, s := range m.sent {
			out = append(out, map[string]any{"id": 500 + i, "to": s["to"], "subject": s["subject"], "status": "sent", "sentAt": "2026-10-02T10:00:00.000Z"})
		}
		jsonResp(w, 200, map[string]any{"emails": out, "hasMore": false})
	case strings.HasPrefix(p, "/api/email/sent-emails/"):
		i, _ := strconv.Atoi(strings.TrimPrefix(p, "/api/email/sent-emails/"))
		s := m.sent[i-500]
		jsonResp(w, 200, map[string]any{"email": map[string]any{"id": i, "to": s["to"], "subject": s["subject"], "htmlContent": s["html"], "sentAt": "2026-10-02T10:00:00.000Z"}})
	case p == "/api/email/upload-attachment":
		m.uploads++
		f, h, err := r.FormFile("file")
		if err != nil {
			jsonResp(w, 400, map[string]string{"error": "未提供文件"})
			return
		}
		b, _ := io.ReadAll(f)
		jsonResp(w, 200, map[string]any{"url": "r2://uploads/u1/x_" + h.Filename, "name": h.Filename, "size": len(b)})
	case p == "/api/email/send":
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		if b["to"] == "blocked@example.net" {
			jsonResp(w, 429, map[string]string{"error": "今日发信数量已达上限", "code": "DAILY_SEND_LIMIT"})
			return
		}
		m.sent = append(m.sent, b)
		jsonResp(w, 200, map[string]any{"message": "ok"})
	default:
		parts := strings.Split(strings.TrimPrefix(p, "/api/email/emails/"), "/")
		id64, err := strconv.Atoi(parts[0])
		e := m.emails[uint32(id64)]
		if err != nil || e == nil {
			jsonResp(w, 404, map[string]string{"error": "邮件不存在"})
			return
		}
		switch {
		case len(parts) == 2 && parts[1] == "raw":
			if e.noRaw {
				jsonResp(w, 404, map[string]string{"error": "原始邮件不存在"})
				return
			}
			w.Header().Set("Content-Type", "message/rfc822")
			io.WriteString(w, m.rawFor(e))
		case len(parts) == 2 && parts[1] == "read":
			var b map[string]bool
			json.NewDecoder(r.Body).Decode(&b)
			e.unread = b["unread"]
			jsonResp(w, 200, map[string]string{"message": "ok"})
		case len(parts) == 2 && parts[1] == "star":
			var b map[string]bool
			json.NewDecoder(r.Body).Decode(&b)
			e.starred = b["starred"]
			jsonResp(w, 200, map[string]string{"message": "ok"})
		case len(parts) == 1 && r.Method == http.MethodDelete:
			e.deleted = true
			jsonResp(w, 200, map[string]string{"message": "删除成功"})
		case len(parts) == 1:
			jsonResp(w, 200, map[string]any{"email": map[string]any{"id": e.id, "subject": e.subject, "sender": "Carol", "senderEmail": e.sender,
				"textContent": "plain body", "htmlContent": "<p>html body</p>", "headers": map[string]any{"to": "me@300031.xyz"},
				"receivedAt": e.received.Format(time.RFC3339)}})
		default:
			jsonResp(w, 404, map[string]string{"error": "not found"})
		}
	}
}

// 按 id 倒序分页，游标为上一页最后一个 id（与真实 API 的「时间_id」游标语义等价）
func (m *mockAPI) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	cursor, _ := strconv.Atoi(q.Get("cursor"))
	var ids []int
	for id, e := range m.emails {
		if (q.Get("filter") == "deleted") != e.deleted {
			continue
		}
		if s := q.Get("search"); s != "" && !strings.Contains(strings.ToLower(e.subject), strings.ToLower(s)) {
			continue
		}
		if cursor > 0 && int(id) >= cursor {
			continue
		}
		ids = append(ids, int(id))
	}
	sort.Sort(sort.Reverse(sort.IntSlice(ids)))
	hasMore := len(ids) > limit
	if hasMore {
		ids = ids[:limit]
	}
	var out []map[string]any
	for _, id := range ids {
		e := m.emails[uint32(id)]
		out = append(out, map[string]any{"id": e.id, "accountId": e.account, "sender": "", "senderEmail": e.sender, "subject": e.subject,
			"unread": e.unread, "starred": e.starred, "receivedAt": e.received.Format(time.RFC3339)})
	}
	var next any
	if hasMore {
		next = strconv.Itoa(ids[len(ids)-1])
	}
	jsonResp(w, 200, map[string]any{"emails": out, "nextCursor": next, "hasMore": hasMore})
}

func (m *mockAPI) called(prefix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// ---------- 测试夹具 ----------

type fixture struct {
	api      *mockAPI
	imapAddr string
	smtpAddr string
	tlsAddr  string
	tlsCfg   *tls.Config
}

func selfSigned(t *testing.T) *tls.Config {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "imap.test"}, DNSNames: []string{"imap.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func startFixture(t *testing.T, maxFails int) *fixture {
	t.Helper()
	m := newMockAPI()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)

	cfg := &proxyConfig{maxMessages: 500, pollInterval: 200 * time.Millisecond, rawCacheMax: 1 << 20, maxRawBytes: 26 << 20, accountDirs: true}
	api := newAPIClient(srv.URL, m.origin, "login", "")
	limiter := newLoginLimiter(maxFails, time.Minute)
	counter := newConnCounter(100, 50)

	mkIMAP := func(insecure bool) *imapserver.Server {
		return imapserver.New(&imapserver.Options{
			NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
				return newIMAPSession(cfg, api, limiter, c), nil, nil
			},
			Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIdle: {}, imap.CapMove: {}, imap.CapSpecialUse: {}},
			InsecureAuth: insecure,
		})
	}
	listen := func() net.Listener {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	f := &fixture{api: m}

	l1 := listen()
	s1 := mkIMAP(true)
	go s1.Serve(counter.wrap(l1))
	f.imapAddr = l1.Addr().String()

	// 隐式 TLS（与生产 993 相同的监听器包装顺序），且不允许明文认证
	f.tlsCfg = selfSigned(t)
	l2 := listen()
	s2 := mkIMAP(false)
	go s2.Serve(tls.NewListener(counter.wrap(l2), f.tlsCfg))
	f.tlsAddr = l2.Addr().String()

	l3 := listen()
	ss := smtp.NewServer(&submissionBackend{cfg: cfg, api: api, limiter: limiter, maxRcpts: 20})
	ss.Domain = "smtp.test"
	ss.AllowInsecureAuth = true
	ss.MaxMessageBytes = 25 << 20
	go ss.Serve(counter.wrap(l3))
	f.smtpAddr = l3.Addr().String()

	t.Cleanup(func() { s1.Close(); s2.Close(); ss.Close() })
	return f
}

func dialIMAP(t *testing.T, addr string, h *imapclient.UnilateralDataHandler) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, &imapclient.Options{UnilateralDataHandler: h})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// ---------- IMAP ----------

func TestIMAPEndToEnd(t *testing.T) {
	f := startFixture(t, 5)
	var mu sync.Mutex
	var exists uint32
	c := dialIMAP(t, f.imapAddr, &imapclient.UnilateralDataHandler{
		Mailbox: func(d *imapclient.UnilateralDataMailbox) {
			if d.NumMessages != nil {
				mu.Lock()
				exists = *d.NumMessages
				mu.Unlock()
			}
		},
	})

	if err := c.Login("user@example.com", "wrong").Wait(); err == nil {
		t.Fatal("错误密码应登录失败")
	}
	if err := c.Login("user@example.com", "pw").Wait(); err != nil {
		t.Fatalf("登录失败: %v", err)
	}

	boxes, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string][]imap.MailboxAttr{}
	for _, b := range boxes {
		names[b.Mailbox] = b.Attrs
	}
	for _, want := range []string{"INBOX", "Sent", "Trash", "Accounts/me@300031.xyz"} {
		if _, ok := names[want]; !ok {
			t.Errorf("LIST 缺少 %s: %v", want, names)
		}
	}
	if !containsAttr(names["Trash"], imap.MailboxAttrTrash) || !containsAttr(names["Sent"], imap.MailboxAttrSent) {
		t.Error("Sent/Trash 应带 SPECIAL-USE 属性，iPhone 据此自动识别")
	}

	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if sel.NumMessages != 3 || sel.UIDValidity == 0 || sel.UIDNext != 14 {
		t.Fatalf("SELECT INBOX: 期望 3 封（不含已删除），UIDNEXT=14，得到 %+v", sel)
	}

	// 列表信息：UID 即主 API 的邮件 id；ENVELOPE 来自原文；无原文的旧邮件用详情合成
	msgs, err := c.Fetch(imap.SeqSetNum(1, 2, 3), &imap.FetchOptions{UID: true, Flags: true, Envelope: true, RFC822Size: true}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 || msgs[0].UID != 11 || msgs[2].UID != 13 {
		t.Fatalf("FETCH 结果不对: %+v", msgs)
	}
	if msgs[0].Envelope == nil || msgs[0].Envelope.Subject != "Hello one" || msgs[0].RFC822Size == 0 {
		t.Errorf("ENVELOPE/SIZE 不对: %+v", msgs[0].Envelope)
	}
	if msgs[2].Envelope == nil || msgs[2].Envelope.Subject != "Old no raw" {
		t.Errorf("无原文邮件应合成 ENVELOPE: %+v", msgs[2].Envelope)
	}
	if containsFlag(msgs[0].Flags, imap.FlagSeen) || !containsFlag(msgs[1].Flags, imap.FlagSeen) {
		t.Errorf("\\Seen 标志应来自主 API 的 unread 字段: %v / %v", msgs[0].Flags, msgs[1].Flags)
	}

	// BODY[]（非 PEEK）读取正文 → 主 API 标记已读
	body, err := c.Fetch(imap.UIDSetNum(11), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}).Collect()
	if err != nil || len(body) != 1 || !strings.Contains(string(body[0].BodySection[0].Bytes), "body of 11") {
		t.Fatalf("取正文失败: %v %+v", err, body)
	}
	if f.api.emails[11].unread {
		t.Error("读取正文后应调用主 API 标记已读")
	}

	// \Flagged → 星标
	if _, err := c.Store(imap.UIDSetNum(12), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagFlagged}}, nil).Collect(); err != nil {
		t.Fatal(err)
	}
	if !f.api.emails[12].starred {
		t.Error("\\Flagged 应同步为主 API 星标")
	}

	// SEARCH
	res, err := c.UIDSearch(&imap.SearchCriteria{Flag: []imap.Flag{imap.FlagFlagged}}, nil).Wait()
	if err != nil || len(res.AllUIDs()) != 1 || res.AllUIDs()[0] != 12 {
		t.Errorf("SEARCH FLAGGED 结果不对: %v %v", err, res)
	}
	res, err = c.UIDSearch(&imap.SearchCriteria{Text: []string{"second"}}, nil).Wait()
	if err != nil || len(res.AllUIDs()) != 1 || res.AllUIDs()[0] != 12 {
		t.Errorf("SEARCH TEXT 应走主 API search: %v %v", err, res)
	}

	// MOVE 到 Trash = 主 API 软删除
	if _, err := c.Move(imap.UIDSetNum(12), "Trash").Wait(); err != nil {
		t.Fatalf("MOVE 失败: %v", err)
	}
	if !f.api.emails[12].deleted {
		t.Error("MOVE 到 Trash 应调用主 API 删除")
	}

	// STORE \Deleted + EXPUNGE 同样走软删除
	c.Store(imap.UIDSetNum(13), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close()
	if _, err := c.Expunge().Collect(); err != nil {
		t.Fatal(err)
	}
	if !f.api.emails[13].deleted {
		t.Error("EXPUNGE 应调用主 API 删除")
	}

	// 新邮件 → NOOP 时推送 EXISTS
	f.api.add("Brand new")
	sess := time.Now()
	_ = sess
	forcePoll(t, c)
	mu.Lock()
	got := exists
	mu.Unlock()
	if got != 2 {
		t.Errorf("新邮件到达后 NOOP 应收到 EXISTS=2（剩 11 + 新邮件），得到 %d", got)
	}

	// Trash 里能看到被删的邮件，但不能彻底删除
	if _, err := c.Select("Trash", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close()
	if _, err := c.Expunge().Collect(); err == nil {
		t.Error("Trash 里 EXPUNGE 应返回 NO（主 API 无单封彻底删除接口）")
	}

	// APPEND 到 Sent：接受但不重复保存
	ap := c.Append("Sent", 5, nil)
	ap.Write([]byte("x\r\n\r\n"))
	ap.Close()
	if _, err := ap.Wait(); err != nil {
		t.Errorf("APPEND Sent 应成功: %v", err)
	}
	ap = c.Append("INBOX", 5, nil)
	ap.Write([]byte("x\r\n\r\n"))
	ap.Close()
	if _, err := ap.Wait(); err == nil {
		t.Error("APPEND INBOX 应被拒绝")
	}
}

// 让下一次 NOOP 越过 10 秒节流
func forcePoll(t *testing.T, c *imapclient.Client) {
	t.Helper()
	pollThrottleOverride = true
	defer func() { pollThrottleOverride = false }()
	if err := c.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
}

func containsAttr(attrs []imap.MailboxAttr, a imap.MailboxAttr) bool {
	for _, x := range attrs {
		if strings.EqualFold(string(x), string(a)) {
			return true
		}
	}
	return false
}

func containsFlag(fs []imap.Flag, f imap.Flag) bool {
	for _, x := range fs {
		if strings.EqualFold(string(x), string(f)) {
			return true
		}
	}
	return false
}

func TestIMAPImpersonationIsReadOnly(t *testing.T) {
	f := startFixture(t, 5)
	c := dialIMAP(t, f.imapAddr, nil)
	if err := c.Login("admin-view@example.com", "pw").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}}, nil).Collect(); err == nil {
		t.Error("模拟会话 STORE 应被拒绝")
	}
	if _, err := c.Move(imap.SeqSetNum(1), "Trash").Wait(); err == nil {
		t.Error("模拟会话 MOVE 应被拒绝")
	}
	// 读正文不应把邮件标成已读
	c.Fetch(imap.UIDSetNum(11), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}).Collect()
	if !f.api.emails[11].unread || f.api.called("POST /api/email/emails/11/read") != 0 {
		t.Error("只读会话读取正文不应调用标记已读")
	}
}

func TestIMAPLoginRateLimit(t *testing.T) {
	f := startFixture(t, 3)
	for i := 0; i < 3; i++ {
		c := dialIMAP(t, f.imapAddr, nil)
		if c.Login("user@example.com", "bad").Wait() == nil {
			t.Fatal("错误密码应失败")
		}
	}
	before := f.api.called("POST /api/auth/login")
	c := dialIMAP(t, f.imapAddr, nil)
	err := c.Login("user@example.com", "pw").Wait()
	if err == nil || !strings.Contains(err.Error(), "LIMIT") {
		t.Errorf("超过失败次数后应直接限流（不再请求主 API），得到 %v", err)
	}
	if f.api.called("POST /api/auth/login") != before {
		t.Error("被限流时不应再请求主 API 登录")
	}
}

// 同一用户多个连接共用一个主 API 会话：否则每次登录都会把其他连接（以及网页）踢下线
func TestIMAPConnectionsShareUpstreamSession(t *testing.T) {
	f := startFixture(t, 5)
	for i := 0; i < 3; i++ {
		c := dialIMAP(t, f.imapAddr, nil)
		if err := c.Login("user@example.com", "pw").Wait(); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.api.called("POST /api/auth/login"); n != 1 {
		t.Errorf("3 个连接应只登录主 API 1 次，实际 %d 次", n)
	}
	// 主 API 会话被网页登录顶掉（令牌失效）后，代理自动重新登录
	f.api.mu.Lock()
	f.api.tokens = map[string]bool{}
	f.api.mu.Unlock()
	c := dialIMAP(t, f.imapAddr, nil)
	if err := c.Login("user@example.com", "pw").Wait(); err != nil {
		t.Fatalf("令牌失效后应自动重新登录: %v", err)
	}
}

func TestIMAPSOverTLSAllowsLogin(t *testing.T) {
	f := startFixture(t, 5)
	c, err := imapclient.DialTLS(f.tlsAddr, &imapclient.Options{TLSConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("user@example.com", "pw").Wait(); err != nil {
		t.Fatalf("993 隐式 TLS 上应允许登录: %v", err)
	}
	// 明文端口（InsecureAuth=false 时）应拒绝登录——这里用 TLS 服务器的配置直接走明文连接验证
	raw, err := net.Dial("tcp", f.tlsAddr)
	if err == nil {
		raw.Close() // TLS 端口不接受明文，连接会在握手阶段失败，这里只确认端口存在
	}
}

func TestIMAPSentFolderListsAPISentMail(t *testing.T) {
	f := startFixture(t, 5)
	f.api.sent = append(f.api.sent, map[string]any{"to": "x@example.net", "subject": "Out going", "html": "<p>hi</p>"})
	c := dialIMAP(t, f.imapAddr, nil)
	c.Login("user@example.com", "pw").Wait()
	sel, err := c.Select("Sent", nil).Wait()
	if err != nil || sel.NumMessages != 1 {
		t.Fatalf("Sent 应有 1 封: %v %+v", err, sel)
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Envelope: true, Flags: true}).Collect()
	if err != nil || msgs[0].Envelope == nil || msgs[0].Envelope.Subject != "Out going" || !containsFlag(msgs[0].Flags, imap.FlagSeen) {
		t.Errorf("已发送邮件应合成 MIME: %v %+v", err, msgs)
	}
}

// ---------- SMTP 提交 ----------

const submission = "From: me@300031.xyz\r\nTo: a@example.net\r\nCc: b@example.net\r\nSubject: =?UTF-8?B?5L2g5aW9?=\r\nMIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=XX\r\n\r\n" +
	"--XX\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello <world>\r\n" +
	"--XX\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n" +
	"--XX--\r\n"

func smtpClient(t *testing.T, addr string) *smtp.Client {
	t.Helper()
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Hello("client.test"); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSMTPSubmission(t *testing.T) {
	f := startFixture(t, 5)

	// 未认证不能发信（防开放中继）
	c := smtpClient(t, f.smtpAddr)
	if err := c.Mail("me@300031.xyz", nil); err == nil {
		t.Fatal("未认证 MAIL FROM 应被拒绝")
	}

	c = smtpClient(t, f.smtpAddr)
	if err := c.Auth(sasl.NewPlainClient("", "user@example.com", "pw")); err != nil {
		t.Fatalf("AUTH PLAIN 失败: %v", err)
	}
	// 不能冒用不属于自己的地址
	if err := c.Mail("ceo@other.com", nil); err == nil {
		t.Fatal("冒用他人地址应被拒绝")
	}
	if err := c.Mail("Me@300031.xyz", nil); err != nil {
		t.Fatal(err)
	}
	c.Rcpt("a@example.net", nil)
	c.Rcpt("b@example.net", nil)
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, submission)
	if err := w.Close(); err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	if f.api.uploads != 1 {
		t.Errorf("附件应上传 1 次（多个收件人复用），实际 %d", f.api.uploads)
	}
	if len(f.api.sent) != 2 {
		t.Fatalf("应按收件人调用 /send 2 次，实际 %d", len(f.api.sent))
	}
	s := f.api.sent[0]
	if s["accountId"] != "acc1" || s["subject"] != "你好" || !strings.Contains(s["html"].(string), "hello &lt;world&gt;") {
		t.Errorf("/send 参数不对: %+v", s)
	}
	atts, _ := s["attachments"].([]any)
	if len(atts) != 1 || !strings.HasPrefix(atts[0].(map[string]any)["url"].(string), "r2://uploads/") {
		t.Errorf("附件引用不对: %+v", s["attachments"])
	}
}

func TestSMTPSubmissionErrorsMapped(t *testing.T) {
	f := startFixture(t, 5)
	c := smtpClient(t, f.smtpAddr)
	if err := c.Auth(sasl.NewLoginClient("user@example.com", "pw")); err != nil {
		t.Fatalf("AUTH LOGIN 失败: %v", err)
	}
	c.Mail("me@300031.xyz", nil)
	c.Rcpt("blocked@example.net", nil)
	w, _ := c.Data()
	io.WriteString(w, "Subject: x\r\n\r\nhi\r\n")
	err := w.Close()
	if e, ok := err.(*smtp.SMTPError); !ok || e.Code != 550 {
		t.Errorf("每日限额应映射为 550，得到 %v", err)
	}
}

func TestSMTPImpersonationCannotSend(t *testing.T) {
	f := startFixture(t, 5)
	c := smtpClient(t, f.smtpAddr)
	if err := c.Auth(sasl.NewPlainClient("", "admin-view@example.com", "pw")); err == nil {
		t.Error("只读模拟会话不应能通过 SMTP 认证")
	}
}

func TestIMAPIdlePushesNewMail(t *testing.T) {
	f := startFixture(t, 5)
	got := make(chan uint32, 4)
	c := dialIMAP(t, f.imapAddr, &imapclient.UnilateralDataHandler{
		Mailbox: func(d *imapclient.UnilateralDataMailbox) {
			if d.NumMessages != nil {
				got <- *d.NumMessages
			}
		},
	})
	if err := c.Login("user@example.com", "pw").Wait(); err != nil {
		t.Fatal(err)
	}
	if !c.Caps().Has(imap.CapIdle) || !c.Caps().Has(imap.CapMove) {
		t.Fatalf("登录后应声明 IDLE 与 MOVE: %v", c.Caps())
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	idle, err := c.Idle()
	if err != nil {
		t.Fatal(err)
	}
	f.api.add("Pushed")
	select {
	case n := <-got:
		if n != 4 {
			t.Errorf("IDLE 中应推送 EXISTS=4，得到 %d", n)
		}
	case <-time.After(3 * time.Second):
		t.Error("IDLE 期间没有推送新邮件")
	}
	idle.Close()
	idle.Wait()
}
