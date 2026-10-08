# Email Forwarder Gateway

主项目（邮箱服务 Mail Client，跑在 Cloudflare）的 **VPS 收信网关**，外加一个**可选的 IMAP/SMTP 客户端代理**。

- **收信网关 `mail-gateway`（默认启动）**：给「MX 指向 VPS 的外部域名」收信。
  自己跑 SMTP（25 端口），收到后**尽快原样** POST 给主项目的 `/api/email/incoming`。
- **客户端代理 `mail-proxy`（可选，默认不启动）**：让 iPhone「邮件」、Thunderbird、Outlook 等客户端
  通过 IMAP（993）/SMTP（465、587）收发主项目邮件，所有读写都转成主项目现有 HTTP API 调用。

## 设计原则：VPS 只做薄转发，随时可换

VPS 不保证长期租用，可能经常更换或掉线，所以：

- **所有业务逻辑和状态都留在 Cloudflare 主 API**：账户、邮件、已读/星标、发信限额、收件人是否存在……全由主 API 判断。
- 网关**不连数据库、不存邮件**。唯一的本地状态是 `endpoints.json`（主项目握手时登记的投递地址与密钥），
  丢了也只需在主项目后台对该路由点一次「轮换」即可恢复。
- 可选的本地重试缓冲**默认关闭**（理由见下文「本地重试缓冲」）。
- 客户端代理**完全无状态**：不落盘、不存邮件，只在每个连接的内存里保存当前会话。
- 换 VPS = 新机器上 `git clone` + 拷 `.env` 与证书 + `docker compose up -d` + 改一条 A 记录，几分钟完成（见「换 VPS」）。

---

## 快速部署

```bash
git clone https://github.com/qiankuishe/email-forwarder.git && cd email-forwarder
cp .env.example .env && chmod 600 .env       # 填写 REGISTER_AUTH_TOKEN 等（见下表）
touch endpoints.json                          # 先建好文件，避免 docker 把它建成目录
mkdir -p certs data
# 放证书（见「TLS 证书」）
docker compose pull
docker compose up -d                          # 只启动收信网关
docker compose --profile proxy up -d          # 需要时再加上 IMAP/SMTP 代理
docker compose logs -f
```

`docker-compose.yml` 默认使用 CI 构建并推送到 Docker Hub 的镜像（`fujiwarashuken/email-forwarder:latest`，
可用 `.env` 里的 `GATEWAY_IMAGE` 指定其他 tag）。两个服务都是：`cap_drop: ALL`（只留绑定低端口的能力）、
只读根文件系统、`no-new-privileges`、日志限量 3×10MB。

> 更新：`docker compose pull && docker compose up -d`（加了代理就再带 `--profile proxy`）。
> 推送到 `main` 会让 CI 更新 Docker Hub 上的 `latest`，VPS 下次 pull 即生效。

---

## 收信网关

### 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `REGISTER_AUTH_TOKEN` | `ceemail`（公开值，**务必更换**） | `/register`、`/unregister` 的准入密钥。用 `openssl rand -hex 32` 生成，与主项目后台「网关路由」里的「网关准入密钥」一致 |
| `REQUIRE_REGISTER_AUTH` | 未设置时：`REGISTER_AUTH_TOKEN` 已改成非默认值则自动 `true`，否则 `false` | **生产必须为 `true`**。为 `false` 时任何能访问 `/register` 的人都能登记自己的 webhook，之后每封来信都会被抄送过去 |
| `REGISTER_AUTH_TOKEN_PREVIOUS` | 空 | 轮换准入密钥时放旧值，新旧两把同时有效，主项目改用新值后删掉 |
| `GATEWAY_DOMAIN` | `mx.300031.xyz` | MX 指向的主机名：SMTP 问候域名、证书名、Authentication-Results 标识 |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | `./certs/<域名>/<域名>` 与 `.key` | STARTTLS 证书。文件更新后**自动热加载**，不用重启 |
| `MAX_MESSAGE_BYTES` | `26214400`（25MB） | 与主 API 的上限一致；超出回 `552` |
| `MAX_SMTP_CONNECTIONS` / `MAX_SMTP_CONNECTIONS_PER_IP` | `200` / `20` | 入站连接上限，超出回 `421` |
| `ALLOW_PRIVATE_WEBHOOKS` | `false` | 是否允许 webhook 指向内网/回环地址（防 SSRF） |
| `REGISTRY_FILE` | `endpoints.json` | 注册表路径 |
| `SPOOL_DIR` | 空（关闭） | 本地重试缓冲目录，如 `/app/data/spool` |
| `SPOOL_MAX_BYTES` / `SPOOL_MAX_AGE_HOURS` | 512MB / 120 | 缓冲上限与最长保留时间 |

### 收信流程

1. 外部 MTA 连到 25 端口，可对同一封信多次 `RCPT TO`；网关收集全部收件人。
2. 做 SPF / DKIM / DMARC 校验（DMARC 组织域按公共后缀表计算），结果以 `X-SPF-Result` 等请求头交给主 API 参考；
   **网关不据此拒信**，是否进垃圾箱由主 API 决定。另附 `X-Gateway-Client-IP`、`X-Gateway-Helo` 供主 API 自行重算。
3. 对「每个收件人 × 每个健康的收件端」POST 原文，使用该收件端握手时登记的密钥。
4. 按主 API 约定决定 SMTP 回复：

| 主 API 返回 | 网关处理 | 回给发件方 |
| --- | --- | --- |
| `2xx` | 已接收（含重复投递） | `250` |
| `404` / `410` / `413`，或带 `permanent:true` 的 `400/422/507` | 永久失败 | `550 5.1.1` / `552 5.3.4` / `554 5.6.0` |
| `401/403/429/5xx`、网络错误、其他 | 临时失败 | `451`，发件方稍后重投 |

- 任一收件人临时失败就整封回 `451`：重投时已成功的收件人会被主 API 按 `(邮箱, Message-ID)` 幂等去重，不会重复。
- 至少一个收件人成功、其余永久失败：回 `250`（SMTP 在 DATA 之后无法逐个拒收）。

### 握手机制

主项目后台创建/轮换「网关路由」时调用：

```bash
curl -X POST https://gw.example.com/register \
  -H "Content-Type: application/json" \
  -H "X-Email-Auth-Token: <REGISTER_AUTH_TOKEN>" \
  -d '{"webhook_url":"https://api.example.com/api/email/incoming","auth_token":"<主项目生成的投递密钥>"}'
```

- 同一 `webhook_url` 重复调用是幂等的（更新密钥和续约时间）；`/unregister` 主动下线。
- `webhook_url` 只允许 `http/https`，拒绝内网/回环地址，且出站请求不跟随重定向。
- 收件端 7 天未续约/探活成功会被自动清理。
- 网关每 15 秒用该端点自己的密钥 POST 一次空请求探活：`400`（邮件为空）=健康；`401/403/404/405/5xx`=不健康。

### 本地重试缓冲（默认关闭）

`SPOOL_DIR` 非空时：主 API 暂时不可用的收件人先落盘（fsync）并回 `250`，后台按 1m→5m→15m→30m→1h→2h→4h
退避重投，使用**当前**登记的端点和密钥（主项目轮换密钥后旧信也能投进去）；超过保留期移入 `failed/` 并在日志告警。

**为什么默认关闭**：回了 `250` 之后，这封信只存在于这台 VPS 的磁盘上；VPS 被回收或更换就丢了。
不开缓冲时网关回 `451`，信由发件方 MTA 保管并重试（通常长达 5 天）——你换了 VPS、改了 A 记录之后，
发件方会自动投到新机器。对「VPS 可能随时更换/掉线」的部署，这样更稳。
只有在 VPS 稳定、而主 API 偶尔长时间不可用时才建议开启。

### 状态面板

`http://127.0.0.1:8088/`（经反代对外）：`2: 连接成功` = 至少一个健康收件端；`1: 未连接` = 没有。

---

## DNS 与「外部域名」接入

主项目自己的域名主要走 Cloudflare Email Routing；这台 VPS 是给**不属于本项目的外部域名**收信的。

### 推荐：所有外部域名的 MX 都指向一个固定主机名

```
; 在你自己控制的域名（例如 300031.xyz）里，只维护这一条：
mx.300031.xyz.     A     <VPS 公网 IP>        ; 必须 DNS-only（Cloudflare 灰云）

; 每个外部域名只需要一条 MX，指向上面的主机名，以后换 VPS 不用再动它们：
@                  MX 10 mx.300031.xyz.
```

这样换 VPS 时**只改 `mx.300031.xyz` 这一条 A 记录**，不需要联系各个外部域名的管理员。
外部域名若直接把 MX 写成 IP 或写成它自己的 A 记录，换 VPS 时就得逐个去改——请尽量统一到固定主机名。
建议把这条 A 记录的 TTL 设为 300 秒，换机时生效快。

### ⚠️ MX 指向的主机名必须是 DNS-only

Cloudflare 橙云（Proxied）不代理 25 端口：外部 MTA 能建立 TCP 连接，但拿不到 `220` 问候，投递全部失败。

```bash
curl -v smtp://mx.300031.xyz:25        # 橙云时会卡住
curl -v smtp://<VPS IP>:25             # 应返回 220 ... ESMTP Service Ready
```

### 网关管理面板走另一个主机名

| 主机名 | 代理状态 | 用途 |
| --- | --- | --- |
| `mx.<域名>` | 灰云 DNS-only | MX 指向它，收 SMTP 25 |
| `gw.<域名>` | 橙云 Proxied | 443 反代到 `127.0.0.1:8088`，供主项目握手与状态面板 |

主项目后台的「网关地址」填 `gw.<域名>`，不要填 MX 主机名。

### 外部域名的 SPF（可选）

网关只收不发，外部域名的 SPF 应按它们自己的发信服务配置，不需要为 VPS 加任何记录。

### PTR（反向解析）

网关**只收信不发信**，PTR 不影响收信。若在 VPS 服务商后台能设置，建议把 PTR 设为 `mx.300031.xyz`
（与 `GATEWAY_DOMAIN`、A 记录三者一致，即 FCrDNS），对日后排障和信誉有好处；换 VPS 时在新服务商后台重设。

### TLS 证书（收信 STARTTLS）

证书必须**公共可信**（外部 MTA 会校验），不要用 Cloudflare Origin CA。推荐宿主机 acme.sh 走 DNS-01
（与 VPS 的 IP 无关，换机后可直接复用或几分钟内重签）：

```bash
acme.sh --issue --dns dns_cf -d mx.300031.xyz --keylength 2048
acme.sh --install-cert -d mx.300031.xyz \
  --fullchain-file /root/email-forwarder/certs/mx.300031.xyz/mx.300031.xyz \
  --key-file       /root/email-forwarder/certs/mx.300031.xyz/mx.300031.xyz.key
# 网关会自动热加载新证书，不需要 reloadcmd 重启容器
```

`dns_cf` 需要一个 Cloudflare API Token：请只授予该 zone 的「DNS:Edit」权限，保存在宿主机的 acme.sh 配置里，
**不要放进本仓库**。验证：`openssl s_client -connect <IP>:25 -starttls smtp -servername mx.300031.xyz`（应 `Verify return code: 0`）。

---

## IMAP/SMTP 客户端代理（可选）

### 能做什么

| 客户端操作 | 代理调用的主 API |
| --- | --- |
| 登录 | `POST /api/auth/login`（同一用户多个连接共用一个会话） |
| 文件夹 `INBOX`（全部邮箱）/ `Accounts/<地址>` | `GET /api/email/emails`、`GET /api/email/accounts/:id/emails` |
| `Trash` | `GET /api/email/emails?filter=deleted` |
| `Sent` | `GET /api/email/accounts/:id/sent-emails`（逐个邮箱合并） |
| 读信 | `GET /api/email/emails/:id/raw`（无原文的旧邮件用详情合成） |
| 已读/未读、旗标 | `POST /api/email/emails/:id/read`、`/star` |
| 删除（移到废纸篓 / `\Deleted`+EXPUNGE） | `DELETE /api/email/emails/:id`（软删除，进 Trash） |
| 发信（465/587） | `POST /api/email/upload-attachment` + 每个收件人一次 `POST /api/email/send` |

- UID 就是主 API 的邮件 id（自增、稳定），代理不维护任何映射表，换 VPS 后客户端缓存仍然有效。
- 新邮件：客户端 IDLE 时每 `IDLE_POLL_SECONDS`（默认 60）秒轮询一次主 API 并推送。
- 安全：必须配置 TLS；登录失败按**客户端 IP**与用户名限流（主 API 看到的 IP 都是 VPS，不能只靠它）；
  只能用本人名下的邮箱作发件人；管理员「模拟登录」的会话只读，不能改标志、删除或发信。

### 已知限制（需要主 API 配合，已整理为主项目的接口需求文档 imap-api-needs.md）

1. **登录会把网页踢下线**：主 API 的 `/login` 会删除该用户的其他会话。代理已让同一用户的所有连接共用一个会话，
   但网页登录与代理登录仍会互相顶掉。主 API 提供「应用专用密码」后，把 `.env` 的 `PROXY_AUTH_MODE` 改为 `app-password` 即可。
2. **需要 `API_ORIGIN`**：主 API 生产环境对写请求做 Origin 校验，代理以 `API_ORIGIN` 冒充一个白名单前端地址。
3. 发信时原始 To/Cc 头不保留（主 API `/send` 只接受单个收件人，代理按收件人逐个发）；不支持 cid 内联图片（作为附件发送）。
4. Trash 里无法「彻底删除」或「恢复」单封邮件（主 API 无对应接口），按保留天数自动清理。
5. 每个文件夹只同步最新 `MAX_MESSAGES_PER_FOLDER`（默认 500）封；列表首次同步需逐封下载原文以取得大小与信头。

### 部署

`.env`：

```bash
API_BASE_URL=https://api.cee.edu.pl
API_ORIGIN=https://mail.300031.xyz        # 主 API FRONTEND_URL 白名单中的任一地址
PROXY_HOSTNAME=mail.300031.xyz
PROXY_AUTH_MODE=login
```

证书（公共可信，覆盖客户端使用的主机名）放到 `certs/proxy/fullchain.pem` 与 `certs/proxy/key.pem`：

```bash
acme.sh --issue --dns dns_cf -d mail.300031.xyz -d imap.300031.xyz -d smtp.300031.xyz
acme.sh --install-cert -d mail.300031.xyz \
  --fullchain-file /root/email-forwarder/certs/proxy/fullchain.pem \
  --key-file       /root/email-forwarder/certs/proxy/key.pem
docker compose --profile proxy up -d
```

防火墙放行 `993`、`465`、`587`（`143` 默认不监听；需要时设 `IMAP_ADDR=:143`，仅支持 STARTTLS 后登录）。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `API_BASE_URL` | （必填） | 主项目 API，必须 https |
| `API_ORIGIN` | 空 | 见上 |
| `AUTH_MODE` | `login` | `login` / `app-password`（compose 中对应 `PROXY_AUTH_MODE`） |
| `APP_LOGIN_PATH` | `/api/auth/app-password/login` | `app-password` 模式调用的接口 |
| `IMAPS_ADDR` / `IMAP_ADDR` / `SMTPS_ADDR` / `SUBMISSION_ADDR` | `:993` / 关 / `:465` / `:587` | 设为空或 `off` 即不监听 |
| `MAX_MESSAGES_PER_FOLDER` | 500 | 每个文件夹同步的最新邮件数 |
| `IDLE_POLL_SECONDS` | 60（最小 10） | IDLE 期间轮询主 API 的间隔 |
| `LOGIN_MAX_FAILS` / `LOGIN_FAIL_WINDOW_MINUTES` | 5 / 15 | 单 IP 失败上限（单用户名为其 2 倍） |
| `MAX_CONNECTIONS` / `MAX_CONNECTIONS_PER_IP` | 500 / 20 | 连接上限 |
| `MAX_RECIPIENTS` | 20 | 单封信收件人上限 |
| `ACCOUNT_FOLDERS` | `true` | 是否为每个邮箱单独列出 `Accounts/<地址>` 文件夹 |

### 客户端 DNS 与自动配置

```
mail.300031.xyz.   A    <VPS IP>     ; DNS-only（灰云），与 mx 同理，CDN 不代理 993/465/587
imap.300031.xyz.   CNAME mail.300031.xyz.
smtp.300031.xyz.   CNAME mail.300031.xyz.

; RFC 6186 服务发现（部分客户端会用）
_imaps._tcp.300031.xyz.       SRV 0 1 993 mail.300031.xyz.
_submissions._tcp.300031.xyz. SRV 0 1 465 mail.300031.xyz.
_submission._tcp.300031.xyz.  SRV 0 1 587 mail.300031.xyz.
```

- **iPhone**：设置 → 邮件 → 账户 → 添加账户 → 其他 → 添加邮件账户；选 **IMAP**，
  收件服务器 `mail.300031.xyz`、发件服务器 `mail.300031.xyz`，用户名为**网页登录邮箱**，密码为登录密码
  （主 API 支持应用专用密码后改用它）。也可以做一个 `.mobileconfig` 描述文件一键安装：
  `com.apple.mail.managed` 负载中填 `IncomingMailServerHostName=mail.300031.xyz`、`IncomingMailServerPortNumber=993`、
  `IncomingMailServerUseSSL=true`、`OutgoingMailServerHostName=mail.300031.xyz`、`OutgoingMailServerPortNumber=465`、
  `OutgoingMailServerUseSSL=true`、`OutgoingPasswordSameAsIncomingPassword=true`，**不要把密码写进描述文件**。
  描述文件建议由主项目前端（Cloudflare Pages）按用户生成下载，而不是放在 VPS 上。
- **Thunderbird**：在主项目前端（Cloudflare Pages）上托管 `https://autoconfig.<域名>/mail/config-v1.1.xml`
  （Mozilla autoconfig），内容为上述主机与端口。放在 Cloudflare 而不是 VPS 上，换 VPS 时无需改动。

---

## 换 VPS（几分钟内迁移）

旧 VPS 上需要带走的只有：`.env`、`certs/`（也可在新机上重签）。`endpoints.json` 可带可不带（不带就在主项目后台点一次「轮换」）。

1. **提前**（可选）：把 `mx.300031.xyz`、`mail.300031.xyz` 的 A 记录 TTL 调到 300 秒。
2. 新 VPS：确认服务商**放行入站 25 端口**（很多云厂商默认封禁 25，需要工单开通）；放行 993/465/587（如用代理）。
3. 部署：
   ```bash
   git clone https://github.com/qiankuishe/email-forwarder.git && cd email-forwarder
   scp old:/root/email-forwarder/.env .            # 或照 .env.example 重新填写
   scp -r old:/root/email-forwarder/certs .        # 或在新机上用 acme.sh DNS-01 重签（与 IP 无关）
   scp old:/root/email-forwarder/endpoints.json . 2>/dev/null || touch endpoints.json
   mkdir -p data
   docker compose pull && docker compose up -d     # 加代理：docker compose --profile proxy up -d
   curl -v smtp://<新 IP>:25                        # 确认 220 问候
   ```
4. 反代：在新机上恢复 `gw.<域名>` → `127.0.0.1:8088` 的 nginx/caddy 配置（若 gw 走 Cloudflare 橙云，只改源站 IP）。
5. **DNS**：把 `mx.300031.xyz`（以及 `mail.`/`gw.` 若在用）的 A 记录改成新 IP。外部域名的 MX 都指向 `mx.300031.xyz`，**无需改动**；
   若有外部域名直接把 MX 写成旧 IP，需要通知其管理员改为 `MX 10 mx.300031.xyz.`。
6. 主项目后台「网关路由」→ 对该路由点「轮换」（会重新握手，登记到新机器；若 gw 主机名变了先修改网关地址）。
7. PTR：在新服务商后台把新 IP 的反向解析设为 `mx.300031.xyz`（可选，见上）。
8. 验证：从外部邮箱给外部域名发一封测试信；`docker compose logs -f mail-gateway` 应看到「邮件处理完成」。
9. 旧 VPS 至少再保留 1 天（等 DNS TTL 过期、发件方的重试切到新 IP），若开了缓冲先确认 `data/spool/` 为空，再销毁。

迁移期间未送达的信不会丢：网关不可达或回 `451` 时，发件方 MTA 会持续重试。

---

## 安全检查清单

- [ ] `.env` 设置强随机 `REGISTER_AUTH_TOKEN` 且 `REQUIRE_REGISTER_AUTH=true`；主项目路由的「网关准入密钥」同步更新
- [ ] `8088` 只绑 `127.0.0.1`，对外仅通过反代的 `gw.` 子域
- [ ] `.env`、`certs/`、`endpoints.json` 权限 600/700，不要提交到仓库（已在 `.gitignore`）
- [ ] 证书为公共可信证书，acme.sh 自动续期
- [ ] 代理（如启用）只监听 TLS 端口，`ALLOW_INSECURE_AUTH` 保持关闭

## 日志

`docker compose logs -f mail-gateway`。记录：每封信的信封（发件人、收件人）、校验结果、每次投递的 HTTP 状态、
握手来源 IP、限流与安全告警。**不记录**邮件正文、任何密钥或密码。日志由 Docker 限量轮转（3×10MB）。

## 开发

```bash
go build ./... && go vet ./... && go test ./...
docker build -t email-forwarder .
```

改动依赖后跑 `go mod tidy` 并提交 `go.mod` / `go.sum`。CI（`.github/workflows/docker-build.yml`）在推送 `main`
或向 `main` 提 PR 时运行 gofmt / vet / test 并构建镜像；配置了 Docker Hub 凭据时推送镜像（`main` → `latest`，PR → `pr-N`）。

```
.
├── main.go / delivery.go / spool.go / limits.go / tlsconf.go   # 收信网关
├── cmd/mail-proxy/                                             # IMAP/SMTP 客户端代理
├── *_test.go, cmd/mail-proxy/proxy_test.go                     # 测试（模拟主 API 的端到端用例）
├── Dockerfile, docker-compose.yml, .env.example
```

技术栈：Go 1.26、emersion/go-smtp、emersion/go-imap v2、emersion/go-msgauth、blitiri.com.ar/go/spf。

## License

MIT License
