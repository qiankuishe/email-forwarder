package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 本地落盘重试缓冲（可选，默认关闭）。
//
// 设计原则：网关只做薄转发，不做业务判断。缓冲只在「主 API 暂时不可用」时生效：
// 先把原文落盘、回 250，再由后台按退避间隔重投，投递成功或主 API 明确永久拒绝后删除。
//
// 为什么默认关闭：一旦回了 250，这封信就只存在于这台 VPS 的磁盘上；
// VPS 若被回收或换掉，缓冲里的信就丢了。不开缓冲时网关回 451，由发件方 MTA
// 自己保管并重试（通常最长 5 天）——换 VPS 后 MX 指向新机器，发件方会投到新机器，
// 对「VPS 可能随时更换/掉线」的部署这反而更稳。
// 只有在 VPS 稳定、而主 API 偶尔长时间不可用时才建议开启（SPOOL_DIR=/app/data/spool）。
type spoolMeta struct {
	ID           string            `json:"id"`
	From         string            `json:"from"`
	Rcpts        []string          `json:"rcpts"`
	ClientIP     string            `json:"client_ip"`
	Helo         string            `json:"helo"`
	Verification EmailVerification `json:"verification"`
	Created      time.Time         `json:"created"`
	Attempts     int               `json:"attempts"`
	NextAttempt  time.Time         `json:"next_attempt"`
}

var (
	spoolDir      = ""                 // SPOOL_DIR，空 = 关闭
	spoolMaxBytes = int64(512 << 20)   // SPOOL_MAX_BYTES，缓冲总大小上限，超出后回 451
	spoolMaxAge   = 5 * 24 * time.Hour // SPOOL_MAX_AGE_HOURS，超时移入 failed/ 并告警
	spoolMu       sync.Mutex           // 串行化重投扫描与写入
	spoolBackoff  = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour}
)

func loadSpoolConfig() {
	spoolDir = strings.TrimSpace(os.Getenv("SPOOL_DIR"))
	if v := envInt("SPOOL_MAX_BYTES", -1); v > 0 {
		spoolMaxBytes = int64(v)
	}
	if v := envInt("SPOOL_MAX_AGE_HOURS", -1); v > 0 {
		spoolMaxAge = time.Duration(v) * time.Hour
	}
	if spoolDir == "" {
		log.Printf("本地重试缓冲: 关闭（主 API 不可用时回 451 由发件方重试）")
		return
	}
	if err := os.MkdirAll(filepath.Join(spoolDir, "failed"), 0700); err != nil {
		log.Printf("❌ 无法创建缓冲目录 %s，已关闭缓冲: %v", spoolDir, err)
		spoolDir = ""
		return
	}
	log.Printf("本地重试缓冲: 开启 dir=%s 上限=%dMB 最长保留=%s", spoolDir, spoolMaxBytes>>20, spoolMaxAge)
}

func spoolEnabled() bool { return spoolDir != "" }

func spoolUsage() int64 {
	var total int64
	entries, _ := os.ReadDir(spoolDir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && !e.IsDir() {
			total += info.Size()
		}
	}
	return total
}

func writeSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// 落盘一封待重投的邮件。先写原文再写元数据（元数据存在 = 提交完成），
// 中途崩溃最多留下孤立的 .eml，不会出现「有元数据没原文」。
func spoolMessage(raw []byte, meta deliveryMeta, rcpts []string) error {
	spoolMu.Lock()
	defer spoolMu.Unlock()
	if spoolUsage()+int64(len(raw)) > spoolMaxBytes {
		return os.ErrInvalid
	}
	b := make([]byte, 12)
	rand.Read(b)
	id := time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b)
	m := spoolMeta{
		ID: id, From: meta.From, Rcpts: rcpts, ClientIP: meta.ClientIP, Helo: meta.Helo,
		Verification: meta.Verification, Created: time.Now(), NextAttempt: time.Now().Add(spoolBackoff[0]),
	}
	if err := writeSync(filepath.Join(spoolDir, id+".eml"), raw); err != nil {
		return err
	}
	data, _ := json.Marshal(m)
	if err := writeSync(filepath.Join(spoolDir, id+".json.tmp"), data); err != nil {
		os.Remove(filepath.Join(spoolDir, id+".eml"))
		return err
	}
	return os.Rename(filepath.Join(spoolDir, id+".json.tmp"), filepath.Join(spoolDir, id+".json"))
}

func healthyEndpointSnapshot() []Endpoint {
	mu.RLock()
	defer mu.RUnlock()
	var eps []Endpoint
	for _, ep := range endpoints {
		if ep.IsHealthy {
			eps = append(eps, *ep)
		}
	}
	return eps
}

// 扫描一次缓冲目录，重投到期的邮件。投递时使用「当前」注册的端点与密钥，
// 所以主项目轮换投递密钥后，缓冲里的旧信会自动用新密钥重投。
func processSpoolOnce(now time.Time) {
	spoolMu.Lock()
	defer spoolMu.Unlock()
	files, _ := filepath.Glob(filepath.Join(spoolDir, "*.json"))
	for _, jf := range files {
		data, err := os.ReadFile(jf)
		if err != nil {
			continue
		}
		var m spoolMeta
		if json.Unmarshal(data, &m) != nil {
			log.Printf("⚠️ 缓冲元数据损坏，移入 failed/: %s", jf)
			moveToFailed(jf)
			continue
		}
		emlPath := strings.TrimSuffix(jf, ".json") + ".eml"
		if now.Sub(m.Created) > spoolMaxAge {
			log.Printf("🚨 缓冲邮件超过 %s 仍未投递成功，移入 failed/ 需人工处理: id=%s from=%s rcpts=%v",
				spoolMaxAge, m.ID, m.From, m.Rcpts)
			moveToFailed(jf)
			moveToFailed(emlPath)
			continue
		}
		if now.Before(m.NextAttempt) {
			continue
		}
		eps := healthyEndpointSnapshot()
		if len(eps) == 0 {
			continue // 没有健康端点，等下一轮，不计入重试次数
		}
		raw, err := os.ReadFile(emlPath)
		if err != nil {
			log.Printf("⚠️ 缓冲原文缺失，移入 failed/: %s", emlPath)
			moveToFailed(jf)
			continue
		}
		meta := deliveryMeta{From: m.From, ClientIP: m.ClientIP, Helo: m.Helo, Verification: m.Verification}
		results := deliverToEndpoints(raw, meta, m.Rcpts, eps)
		var remaining []string
		for _, r := range m.Rcpts {
			switch results[r].outcome {
			case outcomeTransient:
				remaining = append(remaining, r)
			case outcomePermanent:
				log.Printf("🚨 缓冲邮件被主 API 永久拒绝，已丢弃该收件人（不会生成退信）: id=%s rcpt=%s status=%d",
					m.ID, r, results[r].status)
			}
		}
		if len(remaining) == 0 {
			os.Remove(jf)
			os.Remove(emlPath)
			log.Printf("缓冲邮件处理完毕: id=%s（第 %d 次重投）", m.ID, m.Attempts+1)
			continue
		}
		m.Rcpts = remaining
		m.Attempts++
		m.NextAttempt = now.Add(spoolBackoff[min(m.Attempts, len(spoolBackoff)-1)])
		data, _ = json.Marshal(m)
		if err := writeSync(jf+".tmp", data); err == nil {
			os.Rename(jf+".tmp", jf)
		}
	}
}

func moveToFailed(path string) {
	os.Rename(path, filepath.Join(spoolDir, "failed", filepath.Base(path)))
}

func startSpoolWorker() {
	if !spoolEnabled() {
		return
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			processSpoolOnce(time.Now())
		}
	}()
}
