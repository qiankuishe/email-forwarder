package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/emersion/go-smtp"
)

// 单个收件人在所有收件端上的综合投递结果
type rcptOutcome int

const (
	outcomeTransient rcptOutcome = iota // 需要重试（网络错误、401/403/429/5xx 等）
	outcomeAccepted                     // 任一收件端 2xx
	outcomePermanent                    // 所有收件端都明确永久拒绝（404/410/413，或带 permanent:true 的 400/422/507）
)

type rcptResult struct {
	outcome rcptOutcome
	status  int // 永久失败时记下主 API 的状态码，用来挑选 SMTP 回复码
}

// 转发时附带的信封与校验信息
type deliveryMeta struct {
	From         string
	ClientIP     string
	Helo         string
	Verification EmailVerification
}

// 一封邮件同时最多并发多少个 HTTP 投递（收件人 × 收件端），避免 50 个收件人时瞬间打出几十个 25MB 的请求
const maxParallelDeliveries = 8

// 主 API 的约定（api/src/routes/email.ts 的 /incoming）：
//
//	2xx                              → 已接收（含重复投递）
//	404/410/413                      → 永久失败（无此邮箱 / 邮箱过期 / 过大）
//	400/422/507 且响应体 permanent:true → 永久失败
//	401/403/429/5xx、网络错误、其他     → 临时失败，应让发件方稍后重投
//
// 旧实现只认 404，其余一律 451，导致 413/410 这类永远不会成功的邮件被发件方无限重投。
func classifyResponse(status int, body []byte) rcptOutcome {
	switch {
	case status >= 200 && status < 300:
		return outcomeAccepted
	case status == 404 || status == 410 || status == 413:
		return outcomePermanent
	case status == 400 || status == 422 || status == 507:
		var payload struct {
			Permanent bool `json:"permanent"`
		}
		if json.Unmarshal(body, &payload) == nil && payload.Permanent {
			return outcomePermanent
		}
	}
	return outcomeTransient
}

// 把原文按「每个收件人 × 每个收件端」投递出去，返回每个收件人的结果。
// 同一封邮件对主 API 重复投递是安全的：主 API 按 (邮箱, Message-ID) 幂等去重。
func deliverToEndpoints(raw []byte, meta deliveryMeta, rcpts []string, eps []Endpoint) map[string]*rcptResult {
	results := make(map[string]*rcptResult, len(rcpts))
	for _, to := range rcpts {
		results[to] = &rcptResult{outcome: outcomePermanent}
	}
	// 每个收件人：是否有端点接受 / 是否有端点临时失败
	accepted := make(map[string]bool)
	transient := make(map[string]bool)
	var resMu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallelDeliveries)

	for _, to := range rcpts {
		for _, ep := range eps {
			wg.Add(1)
			sem <- struct{}{}
			go func(ep Endpoint, rcptTo string) {
				defer wg.Done()
				defer func() { <-sem }()
				status, body, err := postToEndpoint(ep, raw, meta, rcptTo)

				resMu.Lock()
				defer resMu.Unlock()
				if err != nil {
					log.Printf("[%s] 投递给 %s 失败（网络错误，稍后重试）: %v", ep.WebhookURL, rcptTo, err)
					transient[rcptTo] = true
					return
				}
				switch classifyResponse(status, body) {
				case outcomeAccepted:
					accepted[rcptTo] = true
				case outcomePermanent:
					if results[rcptTo].status == 0 {
						results[rcptTo].status = status
					}
					log.Printf("[%s] 投递给 %s 被永久拒绝: HTTP %d", ep.WebhookURL, rcptTo, status)
				default:
					transient[rcptTo] = true
					log.Printf("[%s] 投递给 %s 临时失败: HTTP %d", ep.WebhookURL, rcptTo, status)
				}
			}(ep, to)
		}
	}
	wg.Wait()

	for _, to := range rcpts {
		switch {
		case accepted[to]:
			results[to].outcome = outcomeAccepted
		case transient[to]:
			results[to].outcome = outcomeTransient
		}
	}
	return results
}

func postToEndpoint(ep Endpoint, raw []byte, meta deliveryMeta, rcptTo string) (int, []byte, error) {
	req, err := http.NewRequest("POST", ep.WebhookURL, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-Email-Auth-Token", ep.AuthToken)
	req.Header.Set("X-Forwarded-From", meta.From)
	req.Header.Set("X-Forwarded-To", rcptTo)
	req.Header.Set("Content-Type", "message/rfc822")
	req.Header.Set("User-Agent", "Email-Gateway")

	req.Header.Set("X-SPF-Result", meta.Verification.SPFResult)
	req.Header.Set("X-DKIM-Result", meta.Verification.DKIMResult)
	req.Header.Set("X-DMARC-Result", meta.Verification.DMARCResult)
	req.Header.Set("X-Auth-Results", meta.Verification.AuthResults)
	// 连接级原始信息也一并交给主 API，便于以后把校验逻辑整体迁回主 API 后在那边重算
	if meta.ClientIP != "" {
		req.Header.Set("X-Gateway-Client-IP", meta.ClientIP)
	}
	if meta.Helo != "" {
		req.Header.Set("X-Gateway-Helo", meta.Helo)
	}

	resp, err := deliveryClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, body, nil
}

// 汇总成一个 SMTP 回复。
//   - 有收件人临时失败：返回 451 让发件方整封重投（已接受的收件人重投时会被主 API 幂等去重，不会重复）。
//     旧实现只要有一个收件人成功就回 250，其余临时失败的收件人直接丢信。
//   - 全部永久失败：按第一个收件人的状态码回 5xx。
//   - 其余（至少一个接受，其余永久失败）：250。
func smtpReplyFor(results map[string]*rcptResult) error {
	anyAccepted, anyTransient := false, false
	var firstPermanent *rcptResult
	for _, r := range results {
		switch r.outcome {
		case outcomeAccepted:
			anyAccepted = true
		case outcomeTransient:
			anyTransient = true
		case outcomePermanent:
			if firstPermanent == nil {
				firstPermanent = r
			}
		}
	}
	if anyTransient {
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Backend temporarily unavailable, try again later"}
	}
	if anyAccepted || firstPermanent == nil {
		return nil
	}
	switch firstPermanent.status {
	case 413:
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too large"}
	case 410:
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "Mailbox expired"}
	case 404:
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "User unknown"}
	default:
		return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "Message rejected"}
	}
}
