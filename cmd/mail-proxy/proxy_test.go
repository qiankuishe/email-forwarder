package main

import (
	"bytes"
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
	gomail "github.com/emersion/go-message/mail"
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
	threadHdr       string         // 原文里追加的信头（In-Reply-To / References 等）
	hdrs            map[string]any // 详情接口的 headers JSON（缺省为 {"to": ...}）
}

type mockAPI struct {
	mu        sync.Mutex
	emails    map[uint32]*mockEmail
	sent      []map[string]any
	sendCalls int // POST /api/email/send 的次数（含被拒的）
	uploads   int
	logins    int
	calls     []string
	origin    string
	nextID    uint32
	tokens    map[string]bool // 有效令牌
	readOnly  map[string]bool
	accounts  []map[string]any
	loginHdr  []http.Header // 每次登录请求的请求头（检查 X-Proxy-Auth / X-Client-IP）
}

func newMockAPI() *mockAPI {
	m := &mockAPI{emails: map[uint32]*mockEmail{}, origin: "https://mail.test", nextID: 100,
		tokens: map[string]bool{}, readOnly: map[string]bool{},
		accounts: []map[string]any{{"id": "acc1", "name": "me@300031.xyz", "type": "permanent"}}}
	base := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	m.emails[11] = &mockEmail{id: 11, account: "acc1", subject: "Hello one", sender: "alice@example.org", unread: true, received: base}
	m.emails[12] = &mockEmail{id: 12, account: "acc1", subject: "Second", sender: "bob@example.org", received: base.Add(time.Hour)}
	m.emails[13] = &mockEmail{id: 13, account: "acc1", subject: "Old no raw", sender: "carol@example.org", noRaw: true, received: base.Add(2 * time.Hour)}
	m.emails[14] = &mockEmail{id: 14, account: "acc1", subject: "Already deleted", sender: "dan@example.org", deleted: true, received: base.Add(3 * time.Hour)}
	return m
}

func (m *mockAPI) rawFor(e *mockEmail) string {
	return fmt.Sprintf("From: %s\r\nTo: me@300031.xyz\r\nSubject: %s\r\nMessage-ID: <m%d@example.org>\r\n%sDate: Thu, 01 Oct 2026 08:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody of %d\r\n",
		e.sender, e.subject, e.id, e.threadHdr, e.id)
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
	if p == "/api/auth/app-password/login" {
		// 与 api/src/routes/auth.ts 一致：平台账号邮箱 → mailbox=null；名下邮箱地址 → mailbox={id,address}
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		m.loginHdr = append(m.loginHdr, r.Header.Clone())
		var mailbox any
		ok := b["appPassword"] == "abcdefghijklmnop"
		if ok && !strings.EqualFold(b["email"], "user@example.com") {
			ok = false
			for _, a := range m.accounts {
				if strings.EqualFold(a["name"].(string), b["email"]) {
					mailbox, ok = map[string]any{"id": a["id"], "address": a["name"]}, true
				}
			}
		}
		if !ok {
			jsonResp(w, 401, map[string]string{"error": "邮箱或应用专用密码错误"})
			return
		}
		m.logins++
		tok := fmt.Sprintf("app-%d", m.logins)
		m.tokens[tok] = true // 应用会话不踢其他会话
		jsonResp(w, 200, map[string]any{"sessionToken": tok, "token": tok, "mailbox": mailbox})
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
		jsonResp(w, 200, map[string]any{"accounts": m.accounts})
	case p == "/api/email/emails":
		m.list(w, r, "")
	case strings.HasPrefix(p, "/api/email/accounts/") && strings.HasSuffix(p, "/emails"):
		m.list(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/api/email/accounts/"), "/emails"))
	case strings.HasPrefix(p, "/api/email/accounts/") && strings.HasSuffix(p, "/sent-emails"):
		// 旧的按邮箱接口：代理不应再调用（审查 M9），测试里断言调用次数为 0
		jsonResp(w, 200, map[string]any{"emails": []any{}, "hasMore": false})
	case p == "/api/email/sent-emails":
		m.listSent(w, r)
	case strings.HasPrefix(p, "/api/email/sent-emails/"):
		i, _ := strconv.Atoi(strings.TrimPrefix(p, "/api/email/sent-emails/"))
		s := m.sent[i-500]
		// 与主 API 一致：返回 sent_emails 整行（含 messageId / inReplyTo / referencesHeader / createdAt / textContent）
		jsonResp(w, 200, map[string]any{"email": map[string]any{"id": i, "to": joinAny(s["to"]), "cc": joinAny(s["cc"]), "subject": s["subject"],
			"htmlContent": s["html"], "textContent": s["text"], "sentAt": sentAtOf(s), "createdAt": "2026-10-02T09:59:57Z",
			"messageId": mockMessageID(s, i), "inReplyTo": s["inReplyTo"], "referencesHeader": s["references"]}})
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
		m.sendCalls++
		if strings.Contains(joinAny(b["to"])+","+joinAny(b["bcc"]), "blocked@example.net") {
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
			hdrs := e.hdrs
			if hdrs == nil {
				hdrs = map[string]any{"to": "me@300031.xyz"}
			}
			jsonResp(w, 200, map[string]any{"email": map[string]any{"id": e.id, "subject": e.subject, "sender": "Carol", "senderEmail": e.sender,
				"textContent": "plain body", "htmlContent": "<p>html body</p>", "headers": hdrs,
				"receivedAt": e.received.Format(time.RFC3339)}})
		default:
			jsonResp(w, 404, map[string]string{"error": "not found"})
		}
	}
}

// 按 id 倒序分页，游标为上一页最后一个 id（与真实 API 的「时间_id」游标语义等价）
func (m *mockAPI) list(w http.ResponseWriter, r *http.Request, account string) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	cursor, _ := strconv.Atoi(q.Get("cursor"))
	var ids []int
	for id, e := range m.emails {
		if account != "" && e.account != account {
			continue
		}
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

// joinAny：/send 的 to / cc / bcc 可以是字符串或数组，统一成逗号分隔串
func joinAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return strings.Join(out, ", ")
	}
	return ""
}

// GET /api/email/sent-emails?cursor=&limit=&accountId=：所有邮箱合并、id 倒序分页，行里带 accountId / fromAddress
func (m *mockAPI) listSent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	cursor, _ := strconv.Atoi(q.Get("cursor"))
	names := map[string]string{}
	for _, a := range m.accounts {
		names[a["id"].(string)] = a["name"].(string)
	}
	var rows []map[string]any
	for i := len(m.sent) - 1; i >= 0; i-- {
		s := m.sent[i]
		id := 500 + i
		acc, _ := s["accountId"].(string)
		if acc == "" {
			acc = "acc1"
		}
		if a := q.Get("accountId"); a != "" && a != acc || cursor > 0 && id >= cursor {
			continue
		}
		rows = append(rows, map[string]any{"id": id, "accountId": acc, "fromAddress": names[acc], "to": joinAny(s["to"]),
			"subject": s["subject"], "status": "sent", "sentAt": sentAtOf(s), "createdAt": "2026-10-02T09:59:57Z",
			"messageId": mockMessageID(s, id)})
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	var next any
	if hasMore {
		next = strconv.Itoa(rows[len(rows)-1]["id"].(int))
	}
	jsonResp(w, 200, map[string]any{"emails": rows, "nextCursor": next, "hasMore": hasMore})
}

// sentAtOf：测试可用 "sentAt": nil 模拟排队中（还没有发送时间）的发信
func sentAtOf(s map[string]any) any {
	if v, ok := s["sentAt"]; ok {
		return v
	}
	return "2026-10-02T10:00:00Z"
}

// mockMessageID：与主 API 一致——客户端给了 Message-ID 就用它，否则服务器生成 <uuid@发件域>
func mockMessageID(s map[string]any, id int) string {
	if v, _ := s["messageId"].(string); v != "" {
		return v
	}
	return fmt.Sprintf("<srv-%d@300031.xyz>", id)
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
	return startFixtureWith(t, maxFails, "login", "", nil)
}

func startFixtureWith(t *testing.T, maxFails int, authMode, secret string, setup func(*mockAPI)) *fixture {
	t.Helper()
	m := newMockAPI()
	if setup != nil {
		setup(m)
	}
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)

	cfg := &proxyConfig{maxMessages: 500, pollInterval: 200 * time.Millisecond, rawCacheMax: 1 << 20, maxRawBytes: 26 << 20, accountDirs: true}
	api := newAPIClient(srv.URL, m.origin, authMode, "/api/auth/app-password/login")
	api.proxySecret = secret
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
	if f.api.sendCalls != 1 || len(f.api.sent) != 1 {
		t.Fatalf("整封信应只调用 /send 1 次，实际 %d", f.api.sendCalls)
	}
	s := f.api.sent[0]
	if s["accountId"] != "acc1" || s["subject"] != "你好" || !strings.Contains(s["html"].(string), "hello &lt;world&gt;") {
		t.Errorf("/send 参数不对: %+v", s)
	}
	if joinAny(s["to"]) != "a@example.net" || joinAny(s["cc"]) != "b@example.net" || s["bcc"] != nil {
		t.Errorf("To/Cc 应取自信头: to=%v cc=%v bcc=%v", s["to"], s["cc"], s["bcc"])
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
	if e, ok := err.(*smtp.SMTPError); !ok || e.Code != 452 {
		t.Errorf("API 429（每日限额）应整封回 452，得到 %v", err)
	}
	if f.api.sendCalls != 1 {
		t.Errorf("/send 应只调用 1 次，实际 %d", f.api.sendCalls)
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

// ---------- 应用专用密码：整个账户 / 单个邮箱 ----------

const testAppPW = "abcdefghijklmnop"
const testSecret = "0123456789abcdef0123456789abcdef-secret"

// 第二个邮箱 two@300031.xyz：21 在收件箱，22 已删除；两个邮箱各有一封已发送
func withSecondMailbox(m *mockAPI) {
	m.accounts = append(m.accounts, map[string]any{"id": "acc2", "name": "two@300031.xyz", "type": "permanent"})
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	m.emails[21] = &mockEmail{id: 21, account: "acc2", subject: "Second box mail", sender: "eve@example.org", unread: true, received: base}
	m.emails[22] = &mockEmail{id: 22, account: "acc2", subject: "Second box trash", sender: "eve@example.org", deleted: true, received: base.Add(time.Hour)}
	m.sent = append(m.sent,
		map[string]any{"accountId": "acc1", "to": "x@example.net", "subject": "From one", "html": "<p>1</p>"},
		map[string]any{"accountId": "acc2", "to": "y@example.net", "subject": "From two", "html": "<p>2</p>"})
}

func listNames(t *testing.T, c *imapclient.Client) map[string]bool {
	t.Helper()
	boxes, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, b := range boxes {
		out[b.Mailbox] = true
	}
	return out
}

func TestAppPasswordAccountLoginSeesAllMailboxes(t *testing.T) {
	f := startFixtureWith(t, 5, "app-password", testSecret, withSecondMailbox)
	c := dialIMAP(t, f.imapAddr, nil)
	if err := c.Login("user@example.com", testAppPW).Wait(); err != nil {
		t.Fatalf("账户登录失败: %v", err)
	}
	names := listNames(t, c)
	for _, want := range []string{"INBOX", "Sent", "Trash", "Accounts/me@300031.xyz", "Accounts/two@300031.xyz"} {
		if !names[want] {
			t.Errorf("整个账户登录 LIST 缺少 %s: %v", want, names)
		}
	}
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil || sel.NumMessages != 4 {
		t.Fatalf("账户 INBOX 应合并两个邮箱共 4 封: %v %+v", err, sel)
	}
	sel, err = c.Select("Sent", nil).Wait()
	if err != nil || sel.NumMessages != 2 {
		t.Fatalf("账户 Sent 应合并两个邮箱共 2 封: %v %+v", err, sel)
	}
	if n := f.api.called("GET /api/email/sent-emails"); n != 1 || f.api.called("GET /api/email/accounts/acc") != 0 {
		t.Errorf("Sent 应只请求合并接口 /api/email/sent-emails（%d 次），不再逐个邮箱请求", n)
	}
	// 登录请求带共享密钥与真实客户端 IP
	f.api.mu.Lock()
	h := f.api.loginHdr[0]
	f.api.mu.Unlock()
	if h.Get("X-Proxy-Auth") != testSecret || h.Get("X-Client-IP") != "127.0.0.1" {
		t.Errorf("登录请求应带 X-Proxy-Auth 与 X-Client-IP，得到 %q %q", h.Get("X-Proxy-Auth"), h.Get("X-Client-IP"))
	}
}

func TestAppPasswordMailboxLoginIsScoped(t *testing.T) {
	f := startFixtureWith(t, 5, "app-password", testSecret, withSecondMailbox)
	c := dialIMAP(t, f.imapAddr, nil)
	if err := c.Login("Two@300031.xyz", testAppPW).Wait(); err != nil {
		t.Fatalf("单邮箱登录失败: %v", err)
	}
	names := listNames(t, c)
	if len(names) != 3 || !names["INBOX"] || !names["Sent"] || !names["Trash"] {
		t.Errorf("单邮箱登录只应有 INBOX/Sent/Trash，得到 %v", names)
	}
	if _, err := c.Select("Accounts/me@300031.xyz", nil).Wait(); err == nil {
		t.Error("单邮箱登录不能 SELECT 其他邮箱")
	}
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil || sel.NumMessages != 1 {
		t.Fatalf("单邮箱 INBOX 应只有 1 封: %v %+v", err, sel)
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{UID: true}).Collect()
	if err != nil || len(msgs) != 1 || msgs[0].UID != 21 {
		t.Fatalf("单邮箱 INBOX 应是 UID 21: %v %+v", err, msgs)
	}
	if f.api.called("GET /api/email/emails") != 0 {
		t.Error("单邮箱登录不应请求合并收件箱 /api/email/emails")
	}
	// 搜索也只在该邮箱内（"one" 只匹配 acc1 的 Hello one）
	res, err := c.UIDSearch(&imap.SearchCriteria{Text: []string{"one"}}, nil).Wait()
	if err != nil || len(res.AllUIDs()) != 0 {
		t.Errorf("单邮箱 SEARCH 不应命中其他邮箱: %v %v", err, res)
	}
	res, err = c.UIDSearch(&imap.SearchCriteria{Text: []string{"box"}}, nil).Wait()
	if err != nil || len(res.AllUIDs()) != 1 || res.AllUIDs()[0] != 21 {
		t.Errorf("单邮箱 SEARCH 结果不对: %v %v", err, res)
	}
	// 其他邮箱的 UID 即使被客户端点名也不会被删除
	c.Move(imap.UIDSetNum(11), "Trash").Wait()
	if f.api.emails[11].deleted || f.api.called("DELETE /api/email/emails/11") != 0 {
		t.Error("单邮箱登录不能删除其他邮箱的邮件")
	}
	if _, err := c.Move(imap.UIDSetNum(21), "Trash").Wait(); err != nil || !f.api.emails[21].deleted {
		t.Errorf("本邮箱 MOVE 到 Trash 应成功: %v", err)
	}
	sel, err = c.Select("Trash", nil).Wait()
	if err != nil || sel.NumMessages != 2 {
		t.Fatalf("单邮箱 Trash 应只含本邮箱的 21、22: %v %+v", err, sel)
	}
	sel, err = c.Select("Sent", nil).Wait()
	if err != nil || sel.NumMessages != 1 {
		t.Fatalf("单邮箱 Sent 应只有本邮箱的 1 封: %v %+v", err, sel)
	}
	if f.api.called("GET /api/email/accounts/acc1/") != 0 {
		t.Error("单邮箱登录不应请求其他邮箱的接口")
	}
	ap := c.Append("Accounts/me@300031.xyz", 5, nil)
	ap.Write([]byte("x\r\n\r\n"))
	ap.Close()
	if _, err := ap.Wait(); err == nil {
		t.Error("单邮箱登录 APPEND 到其他邮箱应失败")
	}
}

// 同一个应用密码、不同用户名是两个范围不同的会话，令牌缓存不能串用
func TestAppPasswordTokenCacheKeyedByUsername(t *testing.T) {
	f := startFixtureWith(t, 5, "app-password", "", withSecondMailbox)
	for _, u := range []string{"two@300031.xyz", "user@example.com", "two@300031.xyz", "user@example.com"} {
		c := dialIMAP(t, f.imapAddr, nil)
		if err := c.Login(u, testAppPW).Wait(); err != nil {
			t.Fatal(err)
		}
		names := listNames(t, c)
		if (u == "user@example.com") != names["Accounts/two@300031.xyz"] {
			t.Errorf("用户名 %s 的范围不对: %v", u, names)
		}
	}
	if n := f.api.called("POST /api/auth/app-password/login"); n != 2 {
		t.Errorf("两个用户名应各登录主 API 1 次（共 2 次），实际 %d", n)
	}
	f.api.mu.Lock()
	h := f.api.loginHdr[0]
	f.api.mu.Unlock()
	if h.Get("X-Proxy-Auth") != "" {
		t.Error("未配置 PROXY_SHARED_SECRET 时不应发送 X-Proxy-Auth")
	}
	c := dialIMAP(t, f.imapAddr, nil)
	if c.Login("nobody@300031.xyz", testAppPW).Wait() == nil {
		t.Error("不属于该用户的地址应登录失败")
	}
}

func TestSMTPMailboxLoginSenderRestricted(t *testing.T) {
	f := startFixtureWith(t, 5, "app-password", testSecret, withSecondMailbox)
	c := smtpClient(t, f.smtpAddr)
	if err := c.Auth(sasl.NewPlainClient("", "two@300031.xyz", testAppPW)); err != nil {
		t.Fatalf("单邮箱 SMTP 认证失败: %v", err)
	}
	if err := c.Mail("me@300031.xyz", nil); err == nil {
		t.Fatal("单邮箱登录不能用同账户的其他地址发信")
	}
	if err := c.Mail("two@300031.xyz", nil); err != nil {
		t.Fatal(err)
	}
	c.Rcpt("a@example.net", nil)
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "Subject: hi\r\n\r\nhello\r\n")
	if err := w.Close(); err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	last := f.api.sent[len(f.api.sent)-1]
	if last["accountId"] != "acc2" {
		t.Errorf("应以 acc2 发信: %+v", last)
	}

	// 整个账户登录仍可用任一地址
	c2 := smtpClient(t, f.smtpAddr)
	if err := c2.Auth(sasl.NewPlainClient("", "user@example.com", testAppPW)); err != nil {
		t.Fatal(err)
	}
	if err := c2.Mail("me@300031.xyz", nil); err != nil {
		t.Errorf("账户登录应能用 me@300031.xyz 发信: %v", err)
	}
}

// ---------- 审查 2026-10-09 M9 / M10 ----------

// 已发送里只带 accountId 的请求：单邮箱登录
func TestSentFolderMailboxLoginPassesAccountID(t *testing.T) {
	f := startFixtureWith(t, 5, "app-password", "", withSecondMailbox)
	c := dialIMAP(t, f.imapAddr, nil)
	if err := c.Login("two@300031.xyz", testAppPW).Wait(); err != nil {
		t.Fatal(err)
	}
	sel, err := c.Select("Sent", nil).Wait()
	if err != nil || sel.NumMessages != 1 {
		t.Fatalf("单邮箱 Sent 应只有 1 封: %v %+v", err, sel)
	}
	f.api.mu.Lock()
	var got []string
	for _, cl := range f.api.calls {
		if strings.HasPrefix(cl, "GET /api/email/sent-emails") {
			got = append(got, cl)
		}
	}
	f.api.mu.Unlock()
	if len(got) != 1 {
		t.Errorf("应请求 /api/email/sent-emails 1 次: %v", got)
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Envelope: true}).Collect()
	if err != nil || len(msgs) != 1 || msgs[0].Envelope.Subject != "From two" ||
		len(msgs[0].Envelope.From) != 1 || msgs[0].Envelope.From[0].Addr() != "two@300031.xyz" {
		t.Errorf("Sent 的发件人应取自 fromAddress: %v %+v", err, msgs)
	}
}

// 回归：第一个邮箱发信很多时，第二个邮箱较新的发信也要出现在 Sent（原来被前一个邮箱占满 500 的额度）
func TestSentFolderNotStarvedByFirstMailbox(t *testing.T) {
	f := startFixtureWith(t, 5, "login", "", func(m *mockAPI) {
		m.accounts = append(m.accounts, map[string]any{"id": "acc2", "name": "two@300031.xyz", "type": "permanent"})
		for i := 0; i < 600; i++ {
			m.sent = append(m.sent, map[string]any{"accountId": "acc1", "to": "x@example.net", "subject": fmt.Sprintf("one-%d", i), "html": "<p>1</p>"})
		}
		m.sent = append(m.sent, map[string]any{"accountId": "acc2", "to": "y@example.net", "subject": "two newest", "html": "<p>2</p>"})
	})
	c := dialIMAP(t, f.imapAddr, nil)
	c.Login("user@example.com", "pw").Wait()
	sel, err := c.Select("Sent", nil).Wait()
	if err != nil || sel.NumMessages != 500 {
		t.Fatalf("Sent 应显示最新 500 封: %v %+v", err, sel)
	}
	if n := f.api.called("GET /api/email/sent-emails"); n != 5 {
		t.Errorf("500 封按每页 100 应分 5 页请求，实际 %d", n)
	}
	msgs, err := c.Fetch(imap.SeqSetNum(500), &imap.FetchOptions{Envelope: true, UID: true}).Collect()
	if err != nil || len(msgs) != 1 || msgs[0].Envelope.Subject != "two newest" {
		t.Fatalf("最新一封应是第二个邮箱的发信: %v %+v", err, msgs)
	}
	if f.api.called("GET /api/email/accounts/acc") != 0 {
		t.Error("不应再逐个邮箱请求 sent-emails")
	}
}

func submitRaw(t *testing.T, f *fixture, from string, rcpts []string, raw string) error {
	t.Helper()
	c := smtpClient(t, f.smtpAddr)
	if err := c.Auth(sasl.NewPlainClient("", "user@example.com", "pw")); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail(from, nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r, nil); err != nil {
			t.Fatalf("RCPT %s: %v", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, raw)
	return w.Close()
}

func TestSMTPOneSendCallWithCcBccAndThreading(t *testing.T) {
	f := startFixture(t, 5)
	// 客户端把 Bcc 头也交上来了（部分客户端会这样）；References 折成两行；d@ 只在信封里
	raw := "From: me@300031.xyz\r\nTo: \"A\" <a@example.net>, ghost@example.net\r\nCc: b@example.net\r\nBcc: c@example.net\r\n" +
		"Subject: Re: hi\r\nIn-Reply-To: <orig-2@example.net>\r\n" +
		"References: <root@example.net>\r\n <orig-2@example.net>\r\n" +
		"Message-ID: <client-1@client>\r\n\r\nreply body\r\n"
	if err := submitRaw(t, f, "me@300031.xyz", []string{"a@example.net", "B@example.net", "c@example.net", "d@example.net"}, raw); err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	f.api.mu.Lock()
	defer f.api.mu.Unlock()
	if f.api.sendCalls != 1 || len(f.api.sent) != 1 {
		t.Fatalf("整封信应只请求 /send 1 次，实际 %d", f.api.sendCalls)
	}
	s := f.api.sent[0]
	if got := joinAny(s["to"]); got != "a@example.net" {
		t.Errorf("to 应只含信头 To 里且在信封中的地址（ghost 不在信封里，不发），得到 %q", got)
	}
	if got := joinAny(s["cc"]); got != "B@example.net" {
		t.Errorf("cc 不对: %q", got)
	}
	if got := joinAny(s["bcc"]); got != "c@example.net, d@example.net" {
		t.Errorf("bcc 应是信封里有、信头 To/Cc 里没有的收件人，得到 %q", got)
	}
	if s["inReplyTo"] != "<orig-2@example.net>" {
		t.Errorf("inReplyTo 不对: %q", s["inReplyTo"])
	}
	if s["references"] != "<root@example.net> <orig-2@example.net>" {
		t.Errorf("references 应原样转交并去掉折行: %q", s["references"])
	}
	if s["messageId"] != "<client-1@client>" {
		t.Errorf("客户端 Message-ID 应转交: %q", s["messageId"])
	}
	// Bcc 只出现在 bcc 字段里：请求体不转交任何原始信头，其余字段里也不出现密送地址
	allowed := map[string]bool{"accountId": true, "to": true, "cc": true, "bcc": true, "inReplyTo": true, "references": true, "messageId": true, "subject": true, "html": true, "attachments": true}
	for k, v := range s {
		if !allowed[k] {
			t.Errorf("请求体不应有字段 %q", k)
		}
		if k == "bcc" {
			continue
		}
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), "c@example.net") || strings.Contains(string(b), "d@example.net") || strings.Contains(strings.ToLower(string(b)), "bcc") {
			t.Errorf("密送地址不能出现在 %s 里: %s", k, b)
		}
	}
}

func TestSMTPAllBccUsesSenderAsTo(t *testing.T) {
	f := startFixture(t, 5)
	raw := "From: me@300031.xyz\r\nTo: undisclosed-recipients:;\r\nSubject: news\r\n\r\nhi\r\n"
	if err := submitRaw(t, f, "me@300031.xyz", []string{"a@example.net", "b@example.net"}, raw); err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	s := f.api.sent[0]
	if joinAny(s["to"]) != "me@300031.xyz" || joinAny(s["bcc"]) != "a@example.net, b@example.net" || f.api.sendCalls != 1 {
		t.Errorf("全是密送时 to 应为发件人、其余进 bcc: %+v", s)
	}
}

func TestSMTPThreadingHeaderInjectionDropped(t *testing.T) {
	// 信头里没法直接塞裸 CR/LF，这里直接测规范化函数：任何换行都被拆开，非 <id> 片段丢弃
	if got := messageIDList("<a@b>\r\nBcc: evil@x.com", 1); got != "<a@b>" {
		t.Errorf("In-Reply-To 注入未被清掉: %q", got)
	}
	if got := messageIDList("<a@b> <c@d>", 1); got != "<a@b>" {
		t.Errorf("In-Reply-To 只能有 1 个 id: %q", got)
	}
	if got := messageIDList("garbage (comment)", 50); got != "" {
		t.Errorf("没有合法 id 时应为空: %q", got)
	}
	var ids []string
	for i := 0; i < 60; i++ {
		ids = append(ids, fmt.Sprintf("<r%d@x>", i))
	}
	got := strings.Fields(messageIDList(strings.Join(ids, "\r\n "), 50))
	if len(got) != 50 || got[0] != "<r0@x>" || got[1] != "<r11@x>" || got[49] != "<r59@x>" {
		t.Errorf("References 超过 50 个应保留第一个和最近 49 个: %v", got)
	}
	for _, g := range got {
		if strings.ContainsAny(g, "\r\n") {
			t.Fatal("References 不能含换行")
		}
	}
}

func TestSMTPBadRecipientRejectedAtRcpt(t *testing.T) {
	f := startFixture(t, 5)
	c := smtpClient(t, f.smtpAddr)
	if err := c.Auth(sasl.NewPlainClient("", "user@example.com", "pw")); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("me@300031.xyz", nil); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"user@-bad.net", "a@b", "a..b@example.net", ".a@example.net", "a@exa_mple.net"} {
		err := c.Rcpt(bad, nil)
		if e, ok := err.(*smtp.SMTPError); !ok || (e.Code != 553 && e.Code != 550) {
			t.Errorf("格式错误的地址 %q 应在 RCPT 阶段回 550/553，得到 %v", bad, err)
		}
	}
	// 坏地址不影响会话里的其他收件人；重复的 RCPT 只算一次
	if err := c.Rcpt("ok@example.net", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("OK@example.net", nil); err != nil {
		t.Fatal(err)
	}
	w, _ := c.Data()
	io.WriteString(w, "To: ok@example.net\r\nSubject: x\r\n\r\nhi\r\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if joinAny(f.api.sent[0]["to"]) != "ok@example.net" || f.api.sent[0]["bcc"] != nil {
		t.Errorf("收件人不对: %+v", f.api.sent[0])
	}
}

func TestMaxRecipientsCappedAtAPILimit(t *testing.T) {
	t.Setenv("MAX_RECIPIENTS", "500")
	if o := loadOptions(); o.maxRcpts != apiMaxRecipients {
		t.Errorf("MAX_RECIPIENTS 应被限制在 %d，得到 %d", apiMaxRecipients, o.maxRcpts)
	}
	t.Setenv("MAX_RECIPIENTS", "20")
	if o := loadOptions(); o.maxRcpts != 20 {
		t.Errorf("MAX_RECIPIENTS=20 应保持 20，得到 %d", o.maxRcpts)
	}
}

// ---------- 回归：iPhone 会话串里「已发送」邮件一直「正在加载」（2026-10-09） ----------

// iPhone 发信：SMTP 提交一封带自己 Message-ID / In-Reply-To / References 的回复，然后把同一封 APPEND 到「已发送」
const iphoneReply = "From: amaeru <me@300031.xyz>\r\nTo: qiankuishe@gmail.com\r\n" +
	"Subject: =?utf-8?B?UmU6IOWbnuWkjeS4suS8muivnea1i+ivlQ==?=\r\n" +
	"Message-Id: <A1B2C3D4-0000-4000-8000-ABCDEF012345@300031.xyz>\r\n" +
	"In-Reply-To: <orig-2@mail.gmail.com>\r\nReferences: <orig-1@mail.gmail.com>\r\n <orig-2@mail.gmail.com>\r\n" +
	"Date: Fri, 9 Oct 2026 15:47:30 +0800\r\nMime-Version: 1.0 (1.0)\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
	"把mio推到在床疯狂摩擦\r\n发自我的 iPhone\r\n"

const iphoneMsgID = "<A1B2C3D4-0000-4000-8000-ABCDEF012345@300031.xyz>"

func fetchSentRaw(t *testing.T, f *fixture, uid imap.UID) (size int64, body []byte) {
	t.Helper()
	c := dialIMAP(t, f.imapAddr, nil)
	if err := c.Login("user@example.com", "pw").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Select("Sent", &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		t.Fatal(err)
	}
	all := &imap.FetchItemBodySection{Peek: true}
	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{UID: true, RFC822Size: true, BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		BodySection: []*imap.FetchItemBodySection{all}}).Collect()
	if err != nil || len(msgs) != 1 {
		t.Fatalf("FETCH 已发送邮件失败: %v %d", err, len(msgs))
	}
	if msgs[0].BodyStructure == nil {
		t.Error("应返回 BODYSTRUCTURE")
	}
	return msgs[0].RFC822Size, msgs[0].FindBodySection(all)
}

func TestSentMailFromIPhoneMatchesAppendedCopyAndFetchesFullBody(t *testing.T) {
	f := startFixture(t, 5)
	if err := submitRaw(t, f, "me@300031.xyz", []string{"qiankuishe@gmail.com"}, iphoneReply); err != nil {
		t.Fatal(err)
	}
	if len(f.api.sent) != 1 || f.api.sent[0]["messageId"] != iphoneMsgID {
		t.Fatalf("SMTP 提交应把客户端 Message-ID 转交主 API: %+v", f.api.sent)
	}

	c := dialIMAP(t, f.imapAddr, nil)
	if err := c.Login("user@example.com", "pw").Wait(); err != nil {
		t.Fatal(err)
	}
	// iPhone 发完把本地副本 APPEND 到「已发送」（代理丢弃，以主 API 的记录为准）
	ap := c.Append("Sent", int64(len(iphoneReply)), &imap.AppendOptions{Flags: []imap.Flag{imap.FlagSeen}})
	ap.Write([]byte(iphoneReply))
	ap.Close()
	if _, err := ap.Wait(); err != nil {
		t.Fatalf("APPEND Sent: %v", err)
	}
	if _, err := c.Select("Sent", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	// 客户端按 Message-ID 找服务器副本：必须找得到，且不需要为比对信头逐封下载详情
	before := f.api.called("GET /api/email/sent-emails/")
	res, err := c.UIDSearch(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: iphoneMsgID}}}, nil).Wait()
	if err != nil || len(res.AllUIDs()) != 1 || res.AllUIDs()[0] != 500 {
		t.Fatalf("按客户端 Message-ID 应找到 UID 500: %v %+v", err, res)
	}
	if n := f.api.called("GET /api/email/sent-emails/") - before; n != 0 {
		t.Errorf("SEARCH HEADER Message-ID 不应下载详情（%d 次）", n)
	}

	size, body := fetchSentRaw(t, f, 500)
	if size == 0 || size != int64(len(body)) {
		t.Fatalf("RFC822.SIZE (%d) 必须等于 BODY[] 实际字节数 (%d)", size, len(body))
	}
	head := strings.ReplaceAll(string(body[:bytes.Index(body, []byte("\r\n\r\n"))]), "\r\n ", " ")
	for _, want := range []string{"Message-Id: " + iphoneMsgID, "In-Reply-To: <orig-2@mail.gmail.com>",
		"References: <orig-1@mail.gmail.com> <orig-2@mail.gmail.com>", "From: <me@300031.xyz>", "To: <qiankuishe@gmail.com>"} {
		if !strings.Contains(head, want) {
			t.Errorf("合成的已发送邮件缺信头 %q:\n%s", want, head)
		}
	}
	if strings.Contains(head, "@mail-proxy") {
		t.Error("不应再用合成的 <sent-N@mail-proxy> 作 Message-ID")
	}
	mr, err := gomail.CreateReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var text string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(p.Body)
		text += string(b)
	}
	if !strings.Contains(text, "把mio推到在床疯狂摩擦") || !strings.Contains(text, "发自我的 iPhone") {
		t.Errorf("正文应完整可读: %q", text)
	}
	// 另一个连接（iPhone 同时开多个）算出的 SIZE 必须一样
	if size2, body2 := fetchSentRaw(t, f, 500); size2 != size || int64(len(body2)) != size {
		t.Errorf("不同连接的 RFC822.SIZE 不一致: %d vs %d", size, size2)
	}
}

func TestQueuedSentMailHasStableDateAndSize(t *testing.T) {
	f := startFixture(t, 5)
	f.api.sent = append(f.api.sent, map[string]any{"to": "x@example.net", "subject": "queued", "html": "<p>排队中</p>", "sentAt": nil})
	size1, body1 := fetchSentRaw(t, f, 500)
	time.Sleep(1100 * time.Millisecond)
	size2, body2 := fetchSentRaw(t, f, 500)
	if size1 != int64(len(body1)) || size2 != size1 {
		t.Errorf("排队中的发信 SIZE 应稳定: %d %d %d", size1, len(body1), size2)
	}
	if !strings.Contains(string(body1), "Date: Fri, 02 Oct 2026 09:59:57 +0000") || !bytes.Contains(body2, []byte("Date: Fri, 02 Oct 2026 09:59:57 +0000")) {
		t.Errorf("没有发送时间时 Date 应取创建时间（不能用当前时间）:\n%s", body1)
	}
}

// ---------- 回归：Apple 邮件里收进来的回信与我们发出的信串不成会话（2026-10-09） ----------
//
// 场景与生产数据一致：我们（iPhone 经代理）发出 Message-ID 为 <7e833bc9-...@amaeru.com> 的信，
// Gmail 回信 In-Reply-To / References 引用它；对方再回一封，References 用 ", " 连接两个 id（主 API headers JSON 的存法）。

const (
	ourMsgID   = "<7e833bc9-756a-4f56-9546-63186110ac5e@amaeru.com>"
	gmailReply = "<CALDP4u=MqeHvkSwohFaMLKmrdOfSCwU7xy+vyPJPQqdBX5F6nQ@mail.gmail.com>"
)

func threadFixture(t *testing.T) (*fixture, *imapclient.Client) {
	f := startFixtureWith(t, 5, "login", "", func(m *mockAPI) {
		// 有原文的回信
		m.emails[20] = &mockEmail{id: 20, account: "acc1", subject: "Re: 会话串接测试2", sender: "qiankuishe@gmail.com",
			received:  time.Date(2026, 10, 9, 7, 55, 0, 0, time.UTC),
			threadHdr: "In-Reply-To: " + ourMsgID + "\r\nReferences: " + ourMsgID + "\r\n"}
		// 没有原文（旧数据）的回信：只能用详情 JSON 合成，线程信头在驼峰键里
		m.emails[21] = &mockEmail{id: 21, account: "acc1", subject: "Re: 会话串接测试2", sender: "qiankuishe@gmail.com", noRaw: true,
			received: time.Date(2026, 10, 9, 7, 57, 0, 0, time.UTC),
			hdrs: map[string]any{"to": "admin@amaeru.com", "messageId": "<CALDP4u=MAq7rH_Vkd=gB1k2cxB=aX-JUq_emtb6UzFgJ_m5cCQ@mail.gmail.com>",
				"inReplyTo": gmailReply, "references": ourMsgID + ", " + gmailReply}}
		// 我们发出的那封（服务器生成的 Message-ID，回复 Gmail 的原信）
		m.sent = append(m.sent, map[string]any{"to": "qiankuishe@gmail.com", "subject": "Re: 会话串接测试2", "html": "<p>打一拳mio</p>",
			"messageId": ourMsgID, "inReplyTo": "<CALDP4ukDTEpjCGkPAj=PGtbwX23aEFZz-Khb6nSvbFO3VMuowA@mail.gmail.com>",
			"references": "<CALDP4ukDTEpjCGkPAj=PGtbwX23aEFZz-Khb6nSvbFO3VMuowA@mail.gmail.com>"})
	})
	c := dialIMAP(t, f.imapAddr, nil)
	if err := c.Login("user@example.com", "pw").Wait(); err != nil {
		t.Fatal(err)
	}
	return f, c
}

var threadFields = &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, Peek: true,
	HeaderFields: []string{"Message-ID", "In-Reply-To", "References"}}

func fetchThread(t *testing.T, c *imapclient.Client, folder string, uid imap.UID) (*imap.Envelope, string) {
	t.Helper()
	if _, err := c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		t.Fatal(err)
	}
	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{UID: true, Envelope: true, BodySection: []*imap.FetchItemBodySection{threadFields}}).Collect()
	if err != nil || len(msgs) != 1 || msgs[0].Envelope == nil {
		t.Fatalf("FETCH %s/%d: %v %+v", folder, uid, err, msgs)
	}
	return msgs[0].Envelope, strings.ReplaceAll(string(msgs[0].FindBodySection(threadFields)), "\r\n ", " ")
}

func TestThreadHeadersIncomingAndSentAgree(t *testing.T) {
	_, c := threadFixture(t)
	strip := func(s string) string { return strings.Trim(s, "<>") }

	// 1. 已发送：ENVELOPE / HEADER.FIELDS 的 Message-ID 必须是真正发出去的那个（对方回信引用的值，大小写和尖括号都一致）
	env, hdr := fetchThread(t, c, "Sent", 500)
	if env.MessageID != strip(ourMsgID) {
		t.Errorf("已发送 ENVELOPE message-id = %q，应为 %q", env.MessageID, strip(ourMsgID))
	}
	if len(env.InReplyTo) != 1 || env.InReplyTo[0] != "CALDP4ukDTEpjCGkPAj=PGtbwX23aEFZz-Khb6nSvbFO3VMuowA@mail.gmail.com" {
		t.Errorf("已发送 ENVELOPE in-reply-to = %v", env.InReplyTo)
	}
	for _, want := range []string{"Message-Id: " + ourMsgID, "In-Reply-To: <CALDP4ukDTEpjCGkPAj=", "References: <CALDP4ukDTEpjCGkPAj="} {
		if !strings.Contains(hdr, want) {
			t.Errorf("已发送 HEADER.FIELDS 缺 %q:\n%s", want, hdr)
		}
	}

	// 2. 收信（有原文）：原样给出，In-Reply-To 指向已发送那封的 Message-ID
	env, hdr = fetchThread(t, c, "INBOX", 20)
	if len(env.InReplyTo) != 1 || env.InReplyTo[0] != strip(ourMsgID) || env.MessageID != "m20@example.org" {
		t.Errorf("收信 ENVELOPE: message-id=%q in-reply-to=%v", env.MessageID, env.InReplyTo)
	}
	if !strings.Contains(hdr, "In-Reply-To: "+ourMsgID) || !strings.Contains(hdr, "References: "+ourMsgID) {
		t.Errorf("收信 HEADER.FIELDS:\n%s", hdr)
	}

	// 3. 收信（无原文，按详情 JSON 合成）：驼峰键里的线程信头也要带上，References 的 ", " 规整成空格分隔
	env, hdr = fetchThread(t, c, "INBOX", 21)
	if env.MessageID != "CALDP4u=MAq7rH_Vkd=gB1k2cxB=aX-JUq_emtb6UzFgJ_m5cCQ@mail.gmail.com" {
		t.Errorf("合成收信 ENVELOPE message-id = %q", env.MessageID)
	}
	if len(env.InReplyTo) != 1 || env.InReplyTo[0] != strip(gmailReply) {
		t.Errorf("合成收信 ENVELOPE in-reply-to = %v", env.InReplyTo)
	}
	if !strings.Contains(hdr, "References: "+ourMsgID+" "+gmailReply) || !strings.Contains(hdr, "In-Reply-To: "+gmailReply) {
		t.Errorf("合成收信 HEADER.FIELDS:\n%s", hdr)
	}
}

func TestMessageIDListAcceptsCommaSeparated(t *testing.T) {
	if got := messageIDList("<a@b>, <c@d>,<e@f>", 50); got != "<a@b> <c@d> <e@f>" {
		t.Errorf("got %q", got)
	}
	if got := messageIDList("<a@b>,\r\n <c@d>", 1); got != "<a@b>" {
		t.Errorf("got %q", got)
	}
}
