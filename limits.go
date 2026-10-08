package main

import (
	"log"
	"net"
	"sync"
	"time"
)

// SMTP 入站连接限制。go-smtp 本身没有连接数限制，单个 IP 开几千个连接
// 就能耗尽文件描述符/内存，让正常来信全部失败。
//
// 超限时直接回 421 并断开（临时失败，正常 MTA 会稍后重试）。
type limitedListener struct {
	net.Listener
	maxTotal int
	maxPerIP int

	mu    sync.Mutex
	total int
	perIP map[string]int
}

func newLimitedListener(l net.Listener, maxTotal, maxPerIP int) *limitedListener {
	return &limitedListener{Listener: l, maxTotal: maxTotal, maxPerIP: maxPerIP, perIP: make(map[string]int)}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := remoteIP(c)
		l.mu.Lock()
		over := (l.maxTotal > 0 && l.total >= l.maxTotal) || (l.maxPerIP > 0 && l.perIP[ip] >= l.maxPerIP)
		if !over {
			l.total++
			l.perIP[ip]++
		}
		l.mu.Unlock()
		if over {
			log.Printf("连接数超限，拒绝来自 %s 的 SMTP 连接", ip)
			c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			c.Write([]byte("421 4.7.0 Too many connections, try again later\r\n"))
			c.Close()
			continue
		}
		return &trackedConn{Conn: c, release: func() { l.release(ip) }}, nil
	}
}

func (l *limitedListener) release(ip string) {
	l.mu.Lock()
	l.total--
	if l.perIP[ip] <= 1 {
		delete(l.perIP, ip)
	} else {
		l.perIP[ip]--
	}
	l.mu.Unlock()
}

func remoteIP(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	return host
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
