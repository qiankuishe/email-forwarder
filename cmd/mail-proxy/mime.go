package main

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"mime"
	"net/mail"
	"strings"
	"time"

	gomail "github.com/emersion/go-message/mail"
)

// buildMIME 在主 API 没有原文（旧数据 / 已发送邮件）时，按详情 JSON 合成一封 RFC 5322 邮件。
// 只在内存里生成，用完即弃。
func buildMIME(from, to, cc, subject string, date time.Time, msgID string, text, htmlBody string) []byte {
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

func headerString(h map[string]any, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
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
