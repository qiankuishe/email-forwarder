package main

import (
	"fmt"
	"testing"
	"time"
)

// L18②（审查 2026-10-09）：随机用户名的失败记录不能无限增长
func TestLoginLimiterSweepsExpiredKeys(t *testing.T) {
	l := newLoginLimiter(5, 50*time.Millisecond)
	for i := 0; i < sweepEvery-1; i++ {
		l.fail("198.51.100.1", fmt.Sprintf("random-%d@example.com", i))
	}
	if _, users := l.size(); users != sweepEvery-1 {
		t.Fatalf("users = %d, want %d", users, sweepEvery-1)
	}
	time.Sleep(80 * time.Millisecond)
	l.fail("198.51.100.2", "fresh@example.com") // 第 sweepEvery 次 fail 触发整表清理
	ips, users := l.size()
	if users != 1 || ips != 1 {
		t.Fatalf("after sweep ips=%d users=%d, want 1/1", ips, users)
	}
}

func TestLoginLimiterCapsTrackedKeys(t *testing.T) {
	l := newLoginLimiter(5, time.Hour)
	for i := 0; i <= maxTrackedKeys; i++ {
		l.fail(fmt.Sprintf("ip-%d", i%100), fmt.Sprintf("u%d", i))
	}
	if _, users := l.size(); users > maxTrackedKeys {
		t.Fatalf("users = %d, want <= %d", users, maxTrackedKeys)
	}
	// 按 IP 的计数不受影响：同一 IP 失败过多仍被拦
	l2 := newLoginLimiter(3, time.Hour)
	for i := 0; i < 3; i++ {
		l2.fail("203.0.113.9", fmt.Sprintf("x%d", i))
	}
	if l2.allow("203.0.113.9", "another") {
		t.Fatal("IP over limit should be blocked")
	}
}
