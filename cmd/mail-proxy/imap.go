package main

// IMAP 会话：把 IMAP 命令翻译成对主 API 的 HTTP 调用。
//
// 无状态原则：
//   - 不落盘，不缓存跨连接的数据。每个连接只在内存里保存「当前选中文件夹的 UID/标志快照」
//     和一个有上限的原文 LRU（同一封信被客户端分几次 FETCH 时不必重复下载）。
//   - UID 直接使用主 API 的邮件自增 id（emails.id / sent_emails.id），天然稳定、递增，
//     因此不需要在代理里维护任何 UID 映射表；UIDVALIDITY 为每个文件夹的固定常数。
//
// 部分搜索/匹配逻辑参考 go-imap v2 的 imapmemserver（MIT License, Copyright (c) 2013 The Go-IMAP Authors）。

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	gomessage "github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

type folderKind int

const (
	kindInbox folderKind = iota
	kindTrash
	kindSent
	kindAccount
)

type folder struct {
	name      string
	kind      folderKind
	accountID string
	attrs     []imap.MailboxAttr
}

func (f *folder) uidValidity() uint32 {
	switch f.kind {
	case kindInbox:
		return 1
	case kindTrash:
		return 2
	case kindSent:
		return 3
	default:
		return crc32.ChecksumIEEE([]byte(f.accountID)) | 0x10000
	}
}

const (
	folderInbox  = "INBOX"
	folderTrash  = "Trash"
	folderSent   = "Sent"
	accountsRoot = "Accounts"
	delim        = '/'
)

type msgMeta struct {
	uid     imap.UID
	seen    bool
	flagged bool
	deleted bool // 仅本连接内的 \Deleted 标记，EXPUNGE 时才真正调用主 API 删除
	date    time.Time
	subject string
	from    string // 发件人（已发送文件夹为收件人）
	sender  string // 仅已发送：发件邮箱地址（/api/email/sent-emails 的 fromAddress）
	msgID   string // 仅已发送：真实 Message-ID（列表里就有，SEARCH HEADER Message-ID 不必下载原文）
	size    int64
}

func (m *msgMeta) flags() []imap.Flag {
	var f []imap.Flag
	if m.seen {
		f = append(f, imap.FlagSeen)
	}
	if m.flagged {
		f = append(f, imap.FlagFlagged)
	}
	if m.deleted {
		f = append(f, imap.FlagDeleted)
	}
	return f
}

type selected struct {
	f        *folder
	msgs     []*msgMeta // 按 UID 升序；下标+1 即序号
	readOnly bool
	lastPoll time.Time
	search   imap.UIDSet
}

type proxyConfig struct {
	maxMessages  int
	pollInterval time.Duration
	rawCacheMax  int64
	maxRawBytes  int64
	accountDirs  bool
}

type imapSession struct {
	cfg     *proxyConfig
	api     *apiClient
	limiter *loginLimiter
	ip      string

	us  *userSession
	sel *selected

	cache *rawCache
}

var _ imapserver.SessionMove = (*imapSession)(nil)

func newIMAPSession(cfg *proxyConfig, api *apiClient, limiter *loginLimiter, conn *imapserver.Conn) *imapSession {
	ip := ""
	if conn != nil {
		if a, ok := conn.NetConn().RemoteAddr().(*net.TCPAddr); ok {
			ip = a.IP.String()
		}
	}
	return &imapSession{cfg: cfg, api: api, limiter: limiter, ip: ip, cache: newRawCache(cfg.rawCacheMax)}
}

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 90*time.Second)
}

var (
	errReadOnly = &imap.Error{Type: imap.StatusResponseTypeNo, Code: "READ-ONLY",
		Text: "只读会话（管理员模拟登录）不能修改邮件"}
	errCannot = func(text string) error {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot, Text: text}
	}
	errNoMailbox = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such mailbox"}
)

func upstreamErr(err error) error {
	var ae *apiError
	if errors.As(err, &ae) {
		if ae.Code == "IMPERSONATION_READ_ONLY" {
			return errReadOnly
		}
		if ae.Status == 429 {
			return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeLimit, Text: "请求过于频繁，请稍后再试"}
		}
		if ae.Status >= 500 {
			return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeUnavailable, Text: "后端暂时不可用"}
		}
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: ae.Msg}
	}
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeUnavailable, Text: "后端暂时不可用"}
}

func (s *imapSession) Close() error { return nil }

func (s *imapSession) Login(username, password string) error {
	c, cancel := ctx()
	defer cancel()
	us, err := authenticate(c, s.api, s.limiter, s.ip, username, password)
	if err != nil {
		if errors.Is(err, errRateLimited) {
			return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeLimit, Text: "登录失败次数过多，请稍后再试"}
		}
		if errors.Is(err, errAuthFailed) {
			return imapserver.ErrAuthFailed
		}
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeUnavailable, Text: "后端暂时不可用"}
	}
	s.us = us
	return nil
}

// ---------- 文件夹 ----------

func (s *imapSession) folders() ([]*folder, error) {
	fs := []*folder{
		{name: folderInbox, kind: kindInbox},
		{name: folderSent, kind: kindSent, attrs: []imap.MailboxAttr{imap.MailboxAttrSent}},
		{name: folderTrash, kind: kindTrash, attrs: []imap.MailboxAttr{imap.MailboxAttrTrash}},
	}
	if s.cfg.accountDirs && s.us.mailbox == nil {
		c, cancel := ctx()
		defer cancel()
		accs, err := s.us.getAccounts(c)
		if err != nil {
			return nil, upstreamErr(err)
		}
		if len(accs) > 0 {
			fs = append(fs, &folder{name: accountsRoot, attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect, imap.MailboxAttrHasChildren}})
		}
		for _, a := range accs {
			fs = append(fs, &folder{name: accountsRoot + string(delim) + a.Name, kind: kindAccount, accountID: a.ID,
				attrs: []imap.MailboxAttr{imap.MailboxAttrHasNoChildren}})
		}
	}
	return fs, nil
}

func (s *imapSession) folder(name string) (*folder, error) {
	if strings.EqualFold(name, folderInbox) {
		name = folderInbox
	}
	fs, err := s.folders()
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		if f.name == name {
			for _, a := range f.attrs {
				if a == imap.MailboxAttrNoSelect {
					return nil, errNoMailbox
				}
			}
			return f, nil
		}
	}
	return nil, errNoMailbox
}

func (s *imapSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	fs, err := s.folders()
	if err != nil {
		return err
	}
	for _, f := range fs {
		match := false
		for _, p := range patterns {
			if imapserver.MatchList(f.name, delim, ref, p) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		if options != nil && options.SelectSpecialUse {
			special := false
			for _, a := range f.attrs {
				if a == imap.MailboxAttrSent || a == imap.MailboxAttrTrash {
					special = true
				}
			}
			if !special {
				continue
			}
		}
		attrs := append([]imap.MailboxAttr{imap.MailboxAttrSubscribed}, f.attrs...)
		if err := w.WriteList(&imap.ListData{Mailbox: f.name, Delim: delim, Attrs: attrs}); err != nil {
			return err
		}
	}
	return nil
}

// listFolder 从主 API 拉取文件夹的最新 limit 封（按 UID 升序返回）
func (s *imapSession) listFolder(f *folder, limit int) ([]*msgMeta, error) {
	c, cancel := ctx()
	defer cancel()
	var out []*msgMeta
	seen := map[imap.UID]bool{}

	add := func(e apiEmailSummary, isSent bool) {
		u := imap.UID(e.ID)
		if seen[u] {
			return
		}
		// 单邮箱登录：兜底过滤掉其他邮箱的邮件（正常情况下已按邮箱请求，不会出现）
		if mb := s.us.mailbox; mb != nil && !isSent && e.AccountID != "" && e.AccountID != mb.ID {
			return
		}
		seen[u] = true
		m := &msgMeta{uid: u, seen: !e.Unread, flagged: e.Starred, date: e.ReceivedAt.Time,
			subject: e.Subject, from: e.SenderEmail, size: e.SizeBytes}
		if e.Sender != "" {
			m.from = e.Sender + " " + e.SenderEmail
		}
		if isSent {
			m.seen, m.date, m.from, m.sender, m.msgID = true, e.SentAt.Time, e.To, e.FromAddress, e.MessageID
			if m.date.IsZero() {
				m.date = e.CreatedAt.Time // 排队中 / 失败的发信没有 sentAt
			}
		}
		out = append(out, m)
	}

	pageAll := func(path string, extra url.Values, isSent bool) error {
		cursor := ""
		for len(out) < limit {
			q := url.Values{"limit": {"100"}}
			for k, v := range extra {
				q[k] = v
			}
			if cursor != "" {
				q.Set("cursor", cursor)
			}
			var page *apiListResp
			err := s.us.call(c, func(tok string) error {
				var err error
				page, err = s.api.listPage(c, tok, path, q)
				return err
			})
			if err != nil {
				return err
			}
			for _, e := range page.Emails {
				add(e, isSent)
			}
			if !page.HasMore || page.NextCursor == nil || *page.NextCursor == "" {
				return nil
			}
			cursor = *page.NextCursor
		}
		return nil
	}

	var err error
	switch f.kind {
	case kindInbox:
		err = pageAll(s.mailListPath(), nil, false)
	case kindTrash:
		err = pageAll(s.mailListPath(), url.Values{"filter": {"deleted"}}, false)
	case kindAccount:
		err = pageAll("/api/email/accounts/"+url.PathEscape(f.accountID)+"/emails", nil, false)
	case kindSent:
		// 合并接口一次分页拉所有邮箱的发信（审查 M9：原来逐个邮箱 pageAll，前面的邮箱会占满 limit 额度）。
		// 单邮箱登录带 accountId，只列该邮箱的。
		var q url.Values
		if mb := s.us.mailbox; mb != nil {
			q = url.Values{"accountId": {mb.ID}}
		}
		err = pageAll("/api/email/sent-emails", q, true)
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].uid < out[j].uid })
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// mailListPath：收件箱 / 已删除的列表接口。整个账户用合并列表，单邮箱登录只请求该邮箱
func (s *imapSession) mailListPath() string {
	if mb := s.us.mailbox; mb != nil {
		return "/api/email/accounts/" + url.PathEscape(mb.ID) + "/emails"
	}
	return "/api/email/emails"
}

func (s *imapSession) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	f, err := s.folder(name)
	if err != nil {
		return nil, err
	}
	msgs, err := s.listFolder(f, s.cfg.maxMessages)
	if err != nil {
		return nil, upstreamErr(err)
	}
	ro := s.us.readOnly || (options != nil && options.ReadOnly)
	s.sel = &selected{f: f, msgs: msgs, readOnly: ro, lastPoll: time.Now()}
	return s.selectData(), nil
}

func (s *imapSession) selectData() *imap.SelectData {
	sel := s.sel
	flags := []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.FlagDeleted}
	perm := flags
	if sel.readOnly {
		perm = nil
	}
	var firstUnseen uint32
	var maxUID imap.UID
	for i, m := range sel.msgs {
		if !m.seen && firstUnseen == 0 {
			firstUnseen = uint32(i + 1)
		}
		if m.uid > maxUID {
			maxUID = m.uid
		}
	}
	return &imap.SelectData{
		Flags:             flags,
		PermanentFlags:    perm,
		NumMessages:       uint32(len(sel.msgs)),
		FirstUnseenSeqNum: firstUnseen,
		UIDNext:           maxUID + 1,
		UIDValidity:       sel.f.uidValidity(),
	}
}

func (s *imapSession) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	f, err := s.folder(name)
	if err != nil {
		return nil, err
	}
	var msgs []*msgMeta
	if s.sel != nil && s.sel.f.name == f.name {
		msgs = s.sel.msgs
	} else if msgs, err = s.listFolder(f, s.cfg.maxMessages); err != nil {
		return nil, upstreamErr(err)
	}
	data := &imap.StatusData{Mailbox: f.name, UIDValidity: f.uidValidity()}
	n := uint32(len(msgs))
	var unseen uint32
	var maxUID imap.UID
	for _, m := range msgs {
		if !m.seen {
			unseen++
		}
		if m.uid > maxUID {
			maxUID = m.uid
		}
	}
	data.UIDNext = maxUID + 1
	if options.NumMessages {
		data.NumMessages = &n
	}
	if options.NumUnseen {
		data.NumUnseen = &unseen
	}
	if options.NumRecent {
		zero := uint32(0)
		data.NumRecent = &zero
	}
	return data, nil
}

func (s *imapSession) Create(string, *imap.CreateOptions) error {
	return errCannot("不支持创建文件夹")
}
func (s *imapSession) Delete(string) error { return errCannot("不支持删除文件夹") }
func (s *imapSession) Rename(string, string, *imap.RenameOptions) error {
	return errCannot("不支持重命名文件夹")
}
func (s *imapSession) Subscribe(string) error   { return nil }
func (s *imapSession) Unsubscribe(string) error { return nil }

// Append：只接受写入「已发送」——iPhone 等客户端发信后会把副本 APPEND 到已发送，
// 而主 API 在 /send 时已经自己记录了已发送邮件，这里读掉内容直接丢弃，避免重复。
func (s *imapSession) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	f, err := s.folder(mailbox)
	if err != nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
	}
	io.Copy(io.Discard, io.LimitReader(r, s.cfg.maxRawBytes))
	if f.kind != kindSent {
		return nil, errCannot("只有「已发送」接受写入（且由服务器自动记录，不会重复保存）")
	}
	if s.us.readOnly {
		return nil, errReadOnly
	}
	return &imap.AppendData{}, nil
}

func (s *imapSession) Unselect() error {
	s.sel = nil
	return nil
}

// ---------- 轮询新邮件 ----------

// 测试用：跳过 NOOP 轮询的 10 秒节流
var pollThrottleOverride = false

func (s *imapSession) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.sel == nil || (!pollThrottleOverride && time.Since(s.sel.lastPoll) < 10*time.Second) {
		return nil
	}
	return s.refresh(w, allowExpunge)
}

// refresh 只拉最新一页（100 封），据此发现新邮件、标志变化，以及该范围内在别处被删除的邮件。
// 更早的邮件变化要等重新 SELECT 才能看到（主 API 目前没有「增量变更」接口，见 imap-api-needs.md）。
func (s *imapSession) refresh(w *imapserver.UpdateWriter, allowExpunge bool) error {
	sel := s.sel
	sel.lastPoll = time.Now()
	latest, err := s.listFolder(sel.f, 100)
	if err != nil {
		log.Printf("轮询失败 user=%s folder=%s: %v", s.us.user, sel.f.name, err)
		return nil // 轮询失败不打断客户端
	}
	if len(latest) == 0 && len(sel.msgs) == 0 {
		return nil
	}
	byUID := make(map[imap.UID]*msgMeta, len(latest))
	var minLatest imap.UID
	for _, m := range latest {
		byUID[m.uid] = m
		if minLatest == 0 || m.uid < minLatest {
			minLatest = m.uid
		}
	}
	var maxKnown imap.UID
	for _, m := range sel.msgs {
		if m.uid > maxKnown {
			maxKnown = m.uid
		}
	}

	// 1. 被删除的（只判断最新一页覆盖的 UID 范围），从高序号往低序号发 EXPUNGE
	if allowExpunge && len(latest) > 0 {
		for i := len(sel.msgs) - 1; i >= 0; i-- {
			m := sel.msgs[i]
			if m.uid >= minLatest && byUID[m.uid] == nil {
				if err := w.WriteExpunge(uint32(i + 1)); err != nil {
					return err
				}
				sel.msgs = append(sel.msgs[:i], sel.msgs[i+1:]...)
			}
		}
	}
	// 2. 标志变化
	for i, m := range sel.msgs {
		if n := byUID[m.uid]; n != nil && (n.seen != m.seen || n.flagged != m.flagged) {
			m.seen, m.flagged = n.seen, n.flagged
			if err := w.WriteMessageFlags(uint32(i+1), m.uid, m.flags()); err != nil {
				return err
			}
		}
	}
	// 3. 新邮件（UID 一定更大，追加在末尾不影响已有序号）
	added := false
	for _, m := range latest {
		if m.uid > maxKnown {
			sel.msgs = append(sel.msgs, m)
			added = true
		}
	}
	if added {
		return w.WriteNumMessages(uint32(len(sel.msgs)))
	}
	return nil
}

func (s *imapSession) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	t := time.NewTicker(s.cfg.pollInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-t.C:
			if s.sel != nil {
				if err := s.refresh(w, true); err != nil {
					return err
				}
			}
		}
	}
}

// ---------- 序号/UID 工具 ----------

func (s *imapSession) staticNumSet(numSet imap.NumSet) imap.NumSet {
	sel := s.sel
	if imap.IsSearchRes(numSet) {
		return sel.search
	}
	switch ns := numSet.(type) {
	case imap.SeqSet:
		max := uint32(len(sel.msgs))
		for i := range ns {
			staticRange(&ns[i].Start, &ns[i].Stop, max)
		}
		return ns
	case imap.UIDSet:
		var max uint32
		if len(sel.msgs) > 0 {
			max = uint32(sel.msgs[len(sel.msgs)-1].uid)
		}
		for i := range ns {
			staticRange((*uint32)(&ns[i].Start), (*uint32)(&ns[i].Stop), max)
		}
		return ns
	}
	return numSet
}

func staticRange(start, stop *uint32, max uint32) {
	dyn := false
	if *start == 0 {
		*start, dyn = max, true
	}
	if *stop == 0 {
		*stop, dyn = max, true
	}
	if dyn && *start > *stop {
		*start, *stop = *stop, *start
	}
}

// forEach 按升序遍历命中的邮件，回调参数为序号（从 1 开始）
func (s *imapSession) forEach(numSet imap.NumSet, f func(seq uint32, m *msgMeta) error) error {
	numSet = s.staticNumSet(numSet)
	for i, m := range s.sel.msgs {
		seq := uint32(i + 1)
		var ok bool
		switch ns := numSet.(type) {
		case imap.SeqSet:
			ok = ns.Contains(seq)
		case imap.UIDSet:
			ok = ns.Contains(m.uid)
		}
		if ok {
			if err := f(seq, m); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------- 原文 ----------

func (s *imapSession) getRaw(m *msgMeta) ([]byte, error) {
	key := fmt.Sprintf("%d/%d", s.sel.f.kind, m.uid)
	if b, ok := s.cache.get(key); ok {
		return b, nil
	}
	c, cancel := ctx()
	defer cancel()
	var raw []byte
	var err error
	if s.sel.f.kind == kindSent {
		var d *apiEmailDetail
		err = s.us.call(c, func(tok string) error {
			d, err = s.api.sentDetail(c, tok, uint32(m.uid))
			return err
		})
		if err == nil {
			raw = s.buildSent(c, m, d)
		}
	} else {
		err = s.us.call(c, func(tok string) error {
			raw, err = s.api.raw(c, tok, uint32(m.uid), s.cfg.maxRawBytes)
			return err
		})
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == 404 {
			// 旧邮件没有保存原文：用详情 JSON 合成一封
			var d *apiEmailDetail
			err = s.us.call(c, func(tok string) error {
				d, err = s.api.detail(c, tok, uint32(m.uid))
				return err
			})
			if err == nil {
				from := d.SenderEmail
				if d.Sender != "" {
					from = fmt.Sprintf("%q <%s>", d.Sender, d.SenderEmail)
				}
				// 线程信头：主 API 的 headers JSON 是驼峰键（messageId / inReplyTo / references），
				// 以前按 "message-id" 找不到，合成的信没有 Message-ID / In-Reply-To / References，会话断开
				raw = buildMIMEHeaders(from, headerString(d.Headers, "to"), headerString(d.Headers, "cc"), d.Subject,
					d.ReceivedAt.Time, messageIDList(headerString(d.Headers, "message-id"), 1), strOr(d.TextContent), strOr(d.HTMLContent),
					map[string]string{
						"In-Reply-To": messageIDList(headerString(d.Headers, "in-reply-to"), 1),
						"References":  messageIDList(headerString(d.Headers, "references"), maxReferences),
					})
			}
		}
	}
	if err != nil {
		return nil, err
	}
	m.size = int64(len(raw))
	s.cache.put(key, raw)
	return raw, nil
}

// buildSent 按已发送详情合成一封信。信头必须与真正发出去的那封一致：
//   - Message-ID 用 sent_emails.message_id（客户端 APPEND 的本地副本、对方回信的 In-Reply-To 都指向它；
//     以前写死成 <sent-N@mail-proxy>，iPhone 永远对不上，本地副本一直「正在加载」，会话也串不起来）
//   - In-Reply-To / References 照原样带上，客户端才能把它归进会话
//   - Date 用发送时间，排队中 / 失败的用创建时间（不能用 time.Now()，否则多次合成的字节数不同，RFC822.SIZE 对不上）
func (s *imapSession) buildSent(c context.Context, m *msgMeta, d *apiEmailDetail) []byte {
	from := m.sender
	if from == "" {
		from = s.fromForSent(c)
	}
	date := d.SentAt.Time
	if date.IsZero() {
		date = d.CreatedAt.Time
	}
	if date.IsZero() {
		date = m.date
	}
	msgID := messageIDList(strOr(d.MessageID), 1)
	if msgID == "" {
		msgID = messageIDList(m.msgID, 1)
	}
	if msgID == "" {
		msgID = fmt.Sprintf("<sent-%d@mail-proxy>", d.ID)
	}
	return buildMIMEHeaders(from, d.To, strOr(d.Cc), d.Subject, date, msgID, strOr(d.TextContent), strOr(d.HTMLContent),
		map[string]string{
			"In-Reply-To": messageIDList(strOr(d.InReplyTo), 1),
			"References":  messageIDList(strOr(d.ReferencesHeader), maxReferences),
		})
}

func (s *imapSession) fromForSent(c context.Context) string {
	// 已发送详情里没有发件地址字段，用账户列表里的第一个邮箱兜底（仅用于显示）
	if accs, err := s.us.getAccounts(c); err == nil && len(accs) > 0 {
		return accs[0].Name
	}
	return s.us.user
}

// ---------- FETCH / STORE / EXPUNGE / MOVE / COPY / SEARCH ----------

func needsRaw(o *imap.FetchOptions, m *msgMeta) bool {
	return (o.RFC822Size && m.size == 0) || o.Envelope || o.BodyStructure != nil ||
		len(o.BodySection) > 0 || len(o.BinarySection) > 0 || len(o.BinarySectionSize) > 0
}

func (s *imapSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	markSeen := false
	for _, bs := range options.BodySection {
		if !bs.Peek {
			markSeen = true
		}
	}
	if s.sel.readOnly || s.sel.f.kind == kindSent {
		markSeen = false
	}
	return s.forEach(numSet, func(seq uint32, m *msgMeta) error {
		var raw []byte
		if needsRaw(options, m) {
			var err error
			if raw, err = s.getRaw(m); err != nil {
				log.Printf("获取原文失败 uid=%d: %v", m.uid, err)
				return upstreamErr(err)
			}
		}
		if markSeen && !m.seen {
			c, cancel := ctx()
			err := s.us.call(c, func(tok string) error { return s.api.setRead(c, tok, uint32(m.uid), true) })
			cancel()
			if err == nil {
				m.seen = true
			}
		}
		rw := w.CreateMessage(seq)
		rw.WriteUID(m.uid)
		if options.Flags || markSeen {
			rw.WriteFlags(m.flags())
		}
		if options.InternalDate {
			rw.WriteInternalDate(m.date)
		}
		if options.RFC822Size {
			rw.WriteRFC822Size(m.size)
		}
		if options.Envelope {
			if h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw))); err == nil {
				rw.WriteEnvelope(imapserver.ExtractEnvelope(h))
			}
		}
		if options.BodyStructure != nil {
			rw.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(raw)))
		}
		for _, bs := range options.BodySection {
			buf := imapserver.ExtractBodySection(bytes.NewReader(raw), bs)
			wc := rw.WriteBodySection(bs, int64(len(buf)))
			if _, err := wc.Write(buf); err != nil {
				wc.Close()
				return err
			}
			if err := wc.Close(); err != nil {
				return err
			}
		}
		for _, bs := range options.BinarySection {
			buf := imapserver.ExtractBinarySection(bytes.NewReader(raw), bs)
			wc := rw.WriteBinarySection(bs, int64(len(buf)))
			if _, err := wc.Write(buf); err != nil {
				wc.Close()
				return err
			}
			if err := wc.Close(); err != nil {
				return err
			}
		}
		for _, bss := range options.BinarySectionSize {
			rw.WriteBinarySectionSize(bss, imapserver.ExtractBinarySectionSize(bytes.NewReader(raw), bss))
		}
		return rw.Close()
	})
}

func (s *imapSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	if s.sel.readOnly {
		return errReadOnly
	}
	want := func(cur bool, flag imap.Flag) bool {
		has := false
		for _, f := range flags.Flags {
			if strings.EqualFold(string(f), string(flag)) {
				has = true
			}
		}
		switch flags.Op {
		case imap.StoreFlagsAdd:
			return cur || has
		case imap.StoreFlagsDel:
			return cur && !has
		default: // Set
			return has
		}
	}
	err := s.forEach(numSet, func(seq uint32, m *msgMeta) error {
		c, cancel := ctx()
		defer cancel()
		seen, flagged, deleted := want(m.seen, imap.FlagSeen), want(m.flagged, imap.FlagFlagged), want(m.deleted, imap.FlagDeleted)
		if s.sel.f.kind != kindSent {
			if seen != m.seen {
				if err := s.us.call(c, func(tok string) error { return s.api.setRead(c, tok, uint32(m.uid), seen) }); err != nil {
					return upstreamErr(err)
				}
				m.seen = seen
			}
			if flagged != m.flagged {
				if err := s.us.call(c, func(tok string) error { return s.api.setStarred(c, tok, uint32(m.uid), flagged) }); err != nil {
					return upstreamErr(err)
				}
				m.flagged = flagged
			}
		}
		m.deleted = deleted
		return nil
	})
	if err != nil {
		return err
	}
	if !flags.Silent {
		return s.Fetch(w, numSet, &imap.FetchOptions{Flags: true, UID: true})
	}
	return nil
}

// canDelete：只有收件箱/邮箱文件夹里的邮件可以删除（主 API 软删除，进入 Trash）
func (s *imapSession) canDelete() error {
	if s.sel.readOnly {
		return errReadOnly
	}
	switch s.sel.f.kind {
	case kindInbox, kindAccount:
		return nil
	case kindTrash:
		return errCannot("主 API 暂不支持彻底删除单封邮件，已删除邮件会按保留天数自动清理")
	default:
		return errCannot("已发送邮件不支持删除")
	}
}

func (s *imapSession) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	var targets []*msgMeta
	for _, m := range s.sel.msgs {
		if m.deleted && (uids == nil || uids.Contains(m.uid)) {
			targets = append(targets, m)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	if err := s.canDelete(); err != nil {
		return err
	}
	return s.removeMessages(targets, w.WriteExpunge)
}

// removeMessages 逐封调用主 API 软删除，从高序号往低序号发 EXPUNGE
func (s *imapSession) removeMessages(targets []*msgMeta, writeExpunge func(uint32) error) error {
	del := map[imap.UID]bool{}
	for _, m := range targets {
		c, cancel := ctx()
		err := s.us.call(c, func(tok string) error { return s.api.deleteEmail(c, tok, uint32(m.uid)) })
		cancel()
		if err != nil {
			var ae *apiError
			if !(errors.As(err, &ae) && ae.Status == 404) { // 已经不存在视为成功
				return upstreamErr(err)
			}
		}
		del[m.uid] = true
	}
	for i := len(s.sel.msgs) - 1; i >= 0; i-- {
		if del[s.sel.msgs[i].uid] {
			if err := writeExpunge(uint32(i + 1)); err != nil {
				return err
			}
			s.sel.msgs = append(s.sel.msgs[:i], s.sel.msgs[i+1:]...)
		}
	}
	return nil
}

func (s *imapSession) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	f, err := s.folder(dest)
	if err != nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
	}
	if f.kind != kindTrash {
		return errCannot("只支持移动到「Trash」（即删除）")
	}
	if err := s.canDelete(); err != nil {
		return err
	}
	var targets []*msgMeta
	s.forEach(numSet, func(_ uint32, m *msgMeta) error { targets = append(targets, m); return nil })
	return s.removeMessages(targets, w.WriteExpunge)
}

// Copy：只把「复制到 Trash」当作 no-op 接受——不支持 MOVE 的客户端删除邮件时会
// COPY 到 Trash 再 STORE \Deleted + EXPUNGE，真正的删除发生在 EXPUNGE。
func (s *imapSession) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	f, err := s.folder(dest)
	if err != nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
	}
	if f.kind == kindTrash && s.canDelete() == nil {
		return &imap.CopyData{}, nil
	}
	return nil, errCannot("不支持复制邮件")
}

func (s *imapSession) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	s.staticCriteria(criteria)
	// 正文/全文条件交给主 API 的 search 参数（匹配主题/发件人/预览），先取得候选集
	var candidates map[imap.UID]bool
	if terms := collectTextTerms(criteria); len(terms) > 0 && s.sel.f.kind != kindSent {
		var err error
		if candidates, err = s.apiSearch(terms[0]); err != nil {
			return nil, upstreamErr(err)
		}
	}
	var data imap.SearchData
	var seqSet imap.SeqSet
	var uidSet imap.UIDSet
	for i, m := range s.sel.msgs {
		seq := uint32(i + 1)
		if !s.match(seq, m, criteria, candidates) {
			continue
		}
		uidSet.AddNum(m.uid)
		num := seq
		if kind == imapserver.NumKindUID {
			num = uint32(m.uid)
		} else {
			seqSet.AddNum(seq)
		}
		if data.Min == 0 || num < data.Min {
			data.Min = num
		}
		if num > data.Max {
			data.Max = num
		}
		data.Count++
	}
	if kind == imapserver.NumKindUID {
		data.All = uidSet
	} else {
		data.All = seqSet
	}
	if options != nil && options.ReturnSave {
		s.sel.search = uidSet
	}
	return &data, nil
}

func collectTextTerms(c *imap.SearchCriteria) []string {
	terms := append(append([]string{}, c.Text...), c.Body...)
	return terms
}

func (s *imapSession) apiSearch(term string) (map[imap.UID]bool, error) {
	c, cancel := ctx()
	defer cancel()
	out := map[imap.UID]bool{}
	path := s.mailListPath()
	q := url.Values{"limit": {"100"}, "search": {term}}
	switch s.sel.f.kind {
	case kindTrash:
		q.Set("filter", "deleted")
	case kindAccount:
		path = "/api/email/accounts/" + url.PathEscape(s.sel.f.accountID) + "/emails"
	}
	var page *apiListResp
	err := s.us.call(c, func(tok string) error {
		var err error
		page, err = s.api.listPage(c, tok, path, q)
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, e := range page.Emails {
		out[imap.UID(e.ID)] = true
	}
	return out, nil
}

func (s *imapSession) staticCriteria(c *imap.SearchCriteria) {
	seqs := make([]imap.SeqSet, 0, len(c.SeqNum))
	for _, ss := range c.SeqNum {
		switch ns := s.staticNumSet(ss).(type) {
		case imap.SeqSet:
			seqs = append(seqs, ns)
		case imap.UIDSet:
			c.UID = append(c.UID, ns)
		}
	}
	c.SeqNum = seqs
	for i := range c.UID {
		c.UID[i] = s.staticNumSet(c.UID[i]).(imap.UIDSet)
	}
	for i := range c.Not {
		s.staticCriteria(&c.Not[i])
	}
	for i := range c.Or {
		s.staticCriteria(&c.Or[i][0])
		s.staticCriteria(&c.Or[i][1])
	}
}

func hasFlag(m *msgMeta, f imap.Flag) bool {
	for _, x := range m.flags() {
		if strings.EqualFold(string(x), string(f)) {
			return true
		}
	}
	return false
}

func dayOnly(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func (s *imapSession) match(seq uint32, m *msgMeta, c *imap.SearchCriteria, candidates map[imap.UID]bool) bool {
	for _, ss := range c.SeqNum {
		if !ss.Contains(seq) {
			return false
		}
	}
	for _, us := range c.UID {
		if !us.Contains(m.uid) {
			return false
		}
	}
	d := dayOnly(m.date)
	if !c.Since.IsZero() && d.Before(c.Since) {
		return false
	}
	if !c.Before.IsZero() && !d.Before(c.Before) {
		return false
	}
	for _, f := range c.Flag {
		if !hasFlag(m, f) {
			return false
		}
	}
	for _, f := range c.NotFlag {
		if hasFlag(m, f) {
			return false
		}
	}
	if (len(c.Text) > 0 || len(c.Body) > 0) && candidates != nil && !candidates[m.uid] {
		return false
	}
	needHeaderRaw := c.Larger != 0 || c.Smaller != 0 || !c.SentSince.IsZero() || !c.SentBefore.IsZero()
	for _, h := range c.Header {
		switch strings.ToLower(h.Key) {
		case "subject":
			if !strings.Contains(strings.ToLower(m.subject), strings.ToLower(h.Value)) {
				return false
			}
		case "from":
			if !strings.Contains(strings.ToLower(m.from), strings.ToLower(h.Value)) {
				return false
			}
		case "message-id":
			// 已发送的列表里带真实 Message-ID：iPhone APPEND 后按 Message-ID 找服务器副本，
			// 不必为了比对信头把整个文件夹每封都下载一遍（数百次详情请求，客户端会一直等）
			if m.msgID == "" {
				needHeaderRaw = true
			} else if !strings.Contains(strings.ToLower(m.msgID), strings.ToLower(h.Value)) {
				return false
			}
		default:
			needHeaderRaw = true
		}
	}
	if needHeaderRaw {
		raw, err := s.getRaw(m)
		if err != nil {
			return false
		}
		if c.Larger != 0 && int64(len(raw)) <= c.Larger {
			return false
		}
		if c.Smaller != 0 && int64(len(raw)) >= c.Smaller {
			return false
		}
		ent, _ := gomessage.Read(bytes.NewReader(raw))
		if ent != nil {
			for _, h := range c.Header {
				k := strings.ToLower(h.Key)
				if k == "subject" || k == "from" || (k == "message-id" && m.msgID != "") {
					continue
				}
				v := strings.ToLower(ent.Header.Get(h.Key))
				if (h.Value == "" && v == "") || !strings.Contains(v, strings.ToLower(h.Value)) {
					return false
				}
			}
			if !c.SentSince.IsZero() || !c.SentBefore.IsZero() {
				t, err := time.Parse(time.RFC1123Z, ent.Header.Get("Date"))
				if err != nil {
					return false
				}
				t = dayOnly(t)
				if (!c.SentSince.IsZero() && t.Before(c.SentSince)) || (!c.SentBefore.IsZero() && !t.Before(c.SentBefore)) {
					return false
				}
			}
		}
	}
	for i := range c.Not {
		if s.match(seq, m, &c.Not[i], candidates) {
			return false
		}
	}
	for i := range c.Or {
		if !s.match(seq, m, &c.Or[i][0], candidates) && !s.match(seq, m, &c.Or[i][1], candidates) {
			return false
		}
	}
	return true
}

// ---------- 每连接的原文 LRU ----------

type rawCache struct {
	max   int64
	size  int64
	order []string
	items map[string][]byte
}

func newRawCache(max int64) *rawCache { return &rawCache{max: max, items: map[string][]byte{}} }

func (c *rawCache) get(k string) ([]byte, bool) {
	b, ok := c.items[k]
	if ok {
		for i, x := range c.order {
			if x == k {
				c.order = append(append(c.order[:i:i], c.order[i+1:]...), k)
				break
			}
		}
	}
	return b, ok
}

func (c *rawCache) put(k string, b []byte) {
	if int64(len(b)) > c.max {
		return
	}
	if _, ok := c.items[k]; ok {
		return
	}
	for c.size+int64(len(b)) > c.max && len(c.order) > 0 {
		old := c.order[0]
		c.order = c.order[1:]
		c.size -= int64(len(c.items[old]))
		delete(c.items, old)
	}
	c.items[k] = b
	c.order = append(c.order, k)
	c.size += int64(len(b))
}
