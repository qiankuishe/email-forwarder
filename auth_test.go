package main

import "testing"

func TestDomainsAlignedUsesPublicSuffix(t *testing.T) {
	cases := []struct {
		a, f   string
		strict bool
		want   bool
	}{
		{"mail.example.com", "example.com", false, true},
		{"example.com", "news.example.com", false, true},
		{"a.co.uk", "b.co.uk", false, false}, // 旧实现会误判为对齐
		{"mail.example.co.uk", "example.co.uk", false, true},
		{"mail.example.com", "example.com", true, false},
		{"evil-example.com", "example.com", false, false},
	}
	for _, c := range cases {
		if got := domainsAligned(c.a, c.f, c.strict); got != c.want {
			t.Errorf("aligned(%s,%s,strict=%v)=%v 期望 %v", c.a, c.f, c.strict, got, c.want)
		}
	}
}

func TestHeaderFromDomainRejectsMultipleFrom(t *testing.T) {
	raw := []byte("From: a@bank.com\r\nFrom: b@evil.test\r\nSubject: x\r\n\r\nhi\r\n")
	if _, ok := headerFromDomain(raw); ok {
		t.Error("多个 From 头应判定为无法对齐")
	}
	raw = []byte("From: \"A\" <a@Example.COM>\r\nSubject: x\r\n\r\nhi\r\n")
	if d, ok := headerFromDomain(raw); !ok || d != "example.com" {
		t.Errorf("单个 From 应解析出 example.com，得到 %q %v", d, ok)
	}
	if v := verifyDMARC([]byte("From: a@bank.com\r\nFrom: b@evil.test\r\n\r\nx"), "pass", "evil.test", "none", nil); v != "permerror" {
		t.Errorf("多 From 的 DMARC 结果应为 permerror，得到 %s", v)
	}
}
