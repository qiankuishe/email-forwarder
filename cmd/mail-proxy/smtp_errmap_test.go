package main

import (
	"errors"
	"testing"

	"github.com/emersion/go-smtp"
)

// 审查第二轮 M4 / L9：主 API 的错误码映射成 SMTP 回复；永久失败 5xx、临时失败 4xx，回复只用 ASCII
func TestSmtpErrFromAPIMapping(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{&apiError{Status: 502, Code: "SEND_FAILED_PERMANENT", Msg: "邮件发送失败"}, 554},
		{&apiError{Status: 502, Code: "SEND_FAILED_TEMPORARY", Msg: "邮件发送失败"}, 451},
		{&apiError{Status: 502, Msg: "邮件发送失败"}, 451},
		{&apiError{Status: 429, Code: "DAILY_SEND_LIMIT", Msg: "今日发信额度已用完"}, 452},
		{&apiError{Status: 400, Code: "TOO_MANY_RECIPIENTS", Msg: "单封邮件最多 20 个收件人"}, 554},
		{&apiError{Status: 422, Code: "RECIPIENT_SUPPRESSED", Msg: "a@b.com：该地址此前硬退信"}, 550},
		{&apiError{Status: 400, Code: "VALIDATION_ERROR", Msg: "收件人邮箱格式不正确"}, 554},
		{&apiError{Status: 410, Code: "ACCOUNT_EXPIRED", Msg: "发件邮箱已过期"}, 554},
		{&apiError{Status: 403, Code: "SEND_SUSPENDED", Msg: "你的发信功能已被暂停"}, 550},
		{errors.New("network down"), 451},
	}
	for _, c := range cases {
		var se *smtp.SMTPError
		if !errors.As(smtpErrFromAPI(c.err), &se) {
			t.Fatalf("%v: not an SMTPError", c.err)
		}
		if se.Code != c.code {
			t.Errorf("%v: code = %d, want %d", c.err, se.Code, c.code)
		}
		for _, r := range se.Message {
			if r > 127 {
				t.Errorf("%v: reply must be ASCII, got %q", c.err, se.Message)
				break
			}
		}
	}
}
