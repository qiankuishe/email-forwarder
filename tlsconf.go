package main

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

// 文件证书热加载：acme.sh 续期后直接覆盖证书文件即可，不必重启容器。
// 每次 TLS 握手最多每 30 秒检查一次文件修改时间，有变化就重新加载；
// 新证书加载失败时继续用旧证书并告警，不会把收信打挂。
type certReloader struct {
	certFile, keyFile string

	mu       sync.Mutex
	cert     *tls.Certificate
	modTime  time.Time
	lastStat time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	st, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	r.cert = &cert
	r.modTime = st.ModTime()
	return nil
}

func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastStat) > 30*time.Second {
		r.lastStat = time.Now()
		if st, err := os.Stat(r.certFile); err == nil && !st.ModTime().Equal(r.modTime) {
			if err := r.load(); err != nil {
				log.Printf("⚠️ 证书文件已变化但重新加载失败，继续使用旧证书: %v", err)
			} else {
				log.Printf("已热加载新证书 %s", r.certFile)
			}
		}
	}
	return r.cert, nil
}
