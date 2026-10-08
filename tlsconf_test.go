package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSigned(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
}

func TestCertReloaderPicksUpRenewedCert(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	writeSelfSigned(t, cp, kp, "old.test")
	r, err := newCertReloader(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := r.GetCertificate(nil)
	writeSelfSigned(t, cp, kp, "new.test")
	os.Chtimes(cp, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	r.lastStat = time.Time{} // 跳过 30 秒节流
	c2, _ := r.GetCertificate(nil)
	l1, _ := x509.ParseCertificate(c1.Certificate[0])
	l2, _ := x509.ParseCertificate(c2.Certificate[0])
	if l1.Subject.CommonName != "old.test" || l2.Subject.CommonName != "new.test" {
		t.Errorf("续期后应加载新证书: %s -> %s", l1.Subject.CommonName, l2.Subject.CommonName)
	}
	// 坏文件不应替换掉可用证书
	os.WriteFile(cp, []byte("garbage"), 0600)
	os.Chtimes(cp, time.Now().Add(2*time.Minute), time.Now().Add(2*time.Minute))
	r.lastStat = time.Time{}
	c3, _ := r.GetCertificate(nil)
	if c3 != c2 {
		t.Error("证书文件损坏时应继续使用旧证书")
	}
}
