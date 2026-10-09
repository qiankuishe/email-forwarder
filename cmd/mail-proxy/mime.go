package main

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"time"

	gomail "github.com/emersion/go-message/mail"
)

// buildMIME 在主 API 没有原文（旧数据 / 已发送邮件）时，按详情 JSON 合成一封 RFC 5322 邮件。
// 只在内存里生成，用完即弃。
func buildMIME(from, to, cc, subject string, date time.Time, msgID string, text, htmlBody string) []byte {
	return buildMIMEHeaders(from, to, cc, subject, date, msgID, text, htmlBody, nil)
}

// buildMIMEHeaders 同 buildMIME，另外写入 extra 里的非空信头（值须已校验、不含换行）
func buildMIMEHeaders(from, to, cc, subject string, date time.Time, msgID string, text, htmlBody string, extra map[string]string) []byte {
	var buf bytes.Buffer
	var h gomail.Header
	if date.IsZero() {
		date = time.Now()
	}
	h.SetDate(date)
	if addrs := parseAddrs(from); len(addrs) > 0 {
		h.SetAddressList("From", addrs)
	}
	if addrs := parseAddrs(to); len(addrs) > 0 {
		h.SetAddressList("To", addrs)
	}
	if addrs := parseAddrs(cc); len(addrs) > 0 {
		h.SetAddressList("Cc", addrs)
	}
	h.SetSubject(subject)
	if msgID != "" {
		h.Set("Message-Id", msgID)
	}
	for _, k := range []string{"In-Reply-To", "References"} {
		if v := extra[k]; v != "" && !strings.ContainsAny(v, "\r\n") {
			h.Set(k, v)
		}
	}

	if htmlBody == "" && text == "" {
		text = " "
	}
	w, err := gomail.CreateWriter(&buf, h)
	if err != nil {
		return nil
	}
	tw, err := w.CreateInline()
	if err != nil {
		return nil
	}
	if text != "" {
		var th gomail.InlineHeader
		th.Set("Content-Type", "text/plain; charset=utf-8")
		if pw, err := tw.CreatePart(th); err == nil {
			io.WriteString(pw, text)
			pw.Close()
		}
	}
	if htmlBody != "" {
		var hh gomail.InlineHeader
		hh.Set("Content-Type", "text/html; charset=utf-8")
		if pw, err := tw.CreatePart(hh); err == nil {
			io.WriteString(pw, htmlBody)
			pw.Close()
		}
	}
	tw.Close()
	w.Close()
	return buf.Bytes()
}

func parseAddrs(s string) []*gomail.Address {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	list, err := mail.ParseAddressList(s)
	if err != nil {
		// 退化：按逗号拆分，原样作为地址
		var out []*gomail.Address
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, &gomail.Address{Address: p})
			}
		}
		return out
	}
	out := make([]*gomail.Address, 0, len(list))
	for _, a := range list {
		out = append(out, &gomail.Address{Name: a.Name, Address: a.Address})
	}
	return out
}

// headerKey 规整信头名：主 API 的 headers JSON 用驼峰（messageId / inReplyTo），这里也接受 message-id 写法
func headerKey(k string) string {
	return strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(k))
}

func headerString(h map[string]any, key string) string {
	for k, v := range h {
		if headerKey(k) == headerKey(key) {
			switch t := v.(type) {
			case string:
				return t
			case []any:
				if len(t) > 0 {
					if s, ok := t[0].(string); ok {
						return s
					}
				}
			case map[string]any:
				if s, ok := t["text"].(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

func strOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ---------- SMTP 提交：把客户端发来的 MIME 拆成主 API /send 需要的字段 ----------

type parsedSubmission struct {
	Subject     string
	HTML        string
	Attachments []parsedAttachment
	// 信头里的收件人（只取地址部分）。Bcc 头即使客户端带了也不读：密送收件人以信封为准，且不能出现在转交的信头里
	To, Cc []string
	// 会话串联信头：已规范成单行的 <msg-id>（空格分隔），不合法的部分被丢弃
	InReplyTo  string
	References string
	// 客户端生成的 Message-ID（单个 <id>，不合法则为空）
	MessageID string
}

type parsedAttachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

func parseSubmission(raw []byte) (*parsedSubmission, error) {
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil && mr == nil {
		return nil, err
	}
	out := &parsedSubmission{}
	if s, err := mr.Header.Subject(); err == nil {
		out.Subject = s
	}
	out.To = headerAddrs(mr.Header, "To")
	out.Cc = headerAddrs(mr.Header, "Cc")
	out.InReplyTo = messageIDList(mr.Header.Get("In-Reply-To"), 1)
	out.References = messageIDList(mr.Header.Get("References"), maxReferences)
	out.MessageID = messageIDList(mr.Header.Get("Message-Id"), 1)
	var textBody, htmlBody string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			if p == nil {
				break
			}
		}
		switch h := p.Header.(type) {
		case *gomail.InlineHeader:
			ct, params, _ := h.ContentType()
			b, _ := io.ReadAll(io.LimitReader(p.Body, 30<<20))
			switch {
			case ct == "text/html" && htmlBody == "":
				htmlBody = string(b)
			case ct == "text/plain" && textBody == "":
				textBody = string(b)
			case strings.HasPrefix(ct, "text/"):
				// 其余文本片段忽略
			default:
				// 内联图片等非文本内联部分按附件发送（主 API 只支持附件，不支持 cid 内联）
				name := params["name"]
				if name == "" {
					name = fmt.Sprintf("inline-%d%s", len(out.Attachments)+1, extFor(ct))
				}
				out.Attachments = append(out.Attachments, parsedAttachment{Filename: name, ContentType: ct, Data: b})
			}
		case *gomail.AttachmentHeader:
			name, _ := h.Filename()
			ct, _, _ := h.ContentType()
			b, _ := io.ReadAll(io.LimitReader(p.Body, 30<<20))
			if name == "" {
				name = fmt.Sprintf("attachment-%d%s", len(out.Attachments)+1, extFor(ct))
			}
			out.Attachments = append(out.Attachments, parsedAttachment{Filename: name, ContentType: ct, Data: b})
		}
	}
	switch {
	case htmlBody != "":
		out.HTML = htmlBody
	case textBody != "":
		out.HTML = "<div style=\"white-space:pre-wrap\">" + html.EscapeString(textBody) + "</div>"
	default:
		out.HTML = "<div></div>"
	}
	if strings.TrimSpace(out.Subject) == "" {
		out.Subject = "(无主题)" // 主 API 要求主题非空
	}
	return out, nil
}

func extFor(ct string) string {
	if exts, _ := mime.ExtensionsByType(ct); len(exts) > 0 {
		return exts[0]
	}
	return ""
}

// headerAddrs 解析 To / Cc 信头里的地址（含组语法）。整体解析失败时按逗号逐个解析，跳过坏的那几个。
func headerAddrs(h gomail.Header, key string) []string {
	var out []string
	if list, err := h.AddressList(key); err == nil {
		for _, a := range list {
			out = append(out, a.Address)
		}
		return out
	}
	raw := h.Get(key)
	for _, p := range strings.Split(raw, ",") {
		if a, err := mail.ParseAddress(strings.TrimSpace(p)); err == nil {
			out = append(out, a.Address)
		}
	}
	return out
}

// 与主 API messageIdListSchema 一致：每个 id 形如 <...>，不含空白和尖括号，最长 250
var msgIDRe = regexp.MustCompile(`^<[^<>\s]{1,250}>$`)

// References 最多 50 个 id（主 API 的上限）
const maxReferences = 50

// messageIDList 把 In-Reply-To / References 规范成单行、空格分隔的 <msg-id> 列表：
// 折行（CRLF + 空白）和任何换行都变成空格，不合法的片段（注释、裸文本）丢弃。
// 超过 max 个时保留第一个（会话根）和最近的 max-1 个（RFC 5322 3.6.4 的建议）。
// In-Reply-To（max=1）只取第一个合法 id。
func messageIDList(v string, max int) string {
	var ids []string
	// 按空白和逗号切分（结果不会含换行）：主 API 存 References 时把多个 id 用 ", " 连接，部分客户端也会这样写
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n' }) {
		if msgIDRe.MatchString(f) {
			ids = append(ids, f)
		}
	}
	if len(ids) == 0 {
		return ""
	}
	if len(ids) > max {
		if max == 1 {
			ids = ids[:1]
		} else {
			ids = append(ids[:1:1], ids[len(ids)-(max-1):]...)
		}
	}
	return strings.Join(ids, " ")
}
