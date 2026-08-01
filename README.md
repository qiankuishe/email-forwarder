# Email Forwarder Gateway

基于 Go 的 SMTP 邮件转发网关，支持自动 TLS 证书管理、多收件端注册与并发分发。

作为主项目（临时邮箱 Mail Client）**除 Cloudflare Email Routing 之外**的第二条收件链路：
当域名的 MX 记录直接指向本网关时，网关自己跑一个 SMTP 服务器（端口 25）接收邮件，
校验 SPF/DKIM/DMARC 后转发给主项目的 `/api/email/incoming`。

## 功能特性

- ✅ SMTP 服务器（端口 25），支持自动/手动 TLS 证书
- ✅ 真实 SPF / DKIM / DMARC 校验（不是简单转发，验证结果会带给主项目）
- ✅ 多收件端注册与健康检查，支持一封邮件并发分发到多个收件端
- ✅ **每个收件端独立密钥**：主项目握手时传入的密钥会被网关保存并在转发邮件时使用，
  不再是网关侧硬编码的固定密钥
- ✅ 正确处理一封邮件多个收件人（`RCPT TO` 多次）的场景，不会丢信
- ✅ HTTP 状态面板、注册/续约/注销接口
- ✅ 持久化存储收件端配置，超时未续约自动清理

## 快速部署

### 使用 Docker（推荐）

```bash
docker run -d \
  --name email-forwarder \
  -p 25:25 \
  -p 8088:8088 \
  -e REQUIRE_REGISTER_AUTH=false \
  -v $(pwd)/certs:/app/certs \
  -v $(pwd)/endpoints.json:/app/endpoints.json \
  --restart unless-stopped \
  fujiwarashuken/email-forwarder:latest
```

### 使用 Docker Compose

```bash
docker-compose up -d
docker-compose logs -f
docker-compose down
```

### CI/CD

本仓库推送到 `main` 分支或提交 PR 时，GitHub Actions（`.github/workflows/docker-build.yml`）
会自动执行 `go build` 并构建 Docker 镜像，是验证代码能否编译通过的主要方式
（本地没有 Go 环境时，以此工作流的结果为准）。若配置了 `DOCKER_USERNAME` /
`DOCKER_PASSWORD` secrets，镜像会推送到 Docker Hub；否则只在 CI 内构建，不推送。

## 配置说明

### 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `REQUIRE_REGISTER_AUTH` | `false` | 是否校验 `/register`、`/unregister` 的 `X-Email-Auth-Token`。**测试阶段默认关闭**，生产环境务必设为 `true` |
| `REGISTER_AUTH_TOKEN` | `ceemail` | 上面校验用的准入密钥。生产环境请覆盖为随机值，不要用默认值 |

当前固定配置（写在 `main.go` 常量里，需要改则改代码重新构建）：
- **网关域名**: `mx.300031.xyz`（用于 TLS 证书申请与 SMTP HELO 域）
- **SMTP 端口**: 25
- **HTTP 端口**: 8088

### 握手机制（重点）

网关不再使用固定密钥转发邮件。每个收件端在握手（`/register`）时可以**自带一个密钥**，
网关会把这个密钥和该收件端的 `webhook_url` 绑定保存，之后转发邮件到这个 `webhook_url`
时就用它自己的密钥，而不是网关的注册准入密钥。这样主项目侧的
`EMAIL_WEBHOOK_SECRET`（或 `inbound_routers.secret_key`）才能和网关转发时携带的
`X-Email-Auth-Token` 真正对上，不需要两边约定一个共享常量。

```bash
# 主项目向网关握手注册
curl -X POST http://mx.300031.xyz:8088/register \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "https://your-backend.com/api/email/incoming",
    "auth_token": "与主项目 EMAIL_WEBHOOK_SECRET 一致的密钥"
  }'
```

- `auth_token` 省略时会回退使用网关的注册准入密钥（兼容旧行为，仅测试用）。
- 同一个 `webhook_url` 再次调用 `/register` 是**幂等的**：会更新密钥和续约时间，不会产生重复记录。
- 收件端超过 7 天未重新握手/未探活成功会被自动清理（`EndpointTTL`），避免 `endpoints.json` 无限增长。

```bash
# 主项目主动下线某个 webhook（可选，不调用的话等 TTL 自动过期）
curl -X POST http://mx.300031.xyz:8088/unregister \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://your-backend.com/api/email/incoming"}'
```

> **测试阶段说明**：`REQUIRE_REGISTER_AUTH=false` 时任何人都能调用 `/register`
> 注册或覆盖 webhook，请勿在暴露公网且已进入生产阶段时继续使用这个模式。
> 上线前请设置 `REQUIRE_REGISTER_AUTH=true` 并配置强随机的 `REGISTER_AUTH_TOKEN`。

### 健康检查

网关每 15 秒对所有注册的收件端发送一次探测请求（**POST**，不再是 GET）：

- 请求会携带该收件端自己的 `auth_token`，并附带 `X-Health-Check: 1` 头
- 主项目的 `/api/email/incoming` 在收到空 body 请求时会返回 400（邮件内容为空），
  这在探测中被视为"服务通、鉴权通"，判定为健康
- 返回 `401`/`403`（密钥不匹配）或 `5xx`/网络错误 才判定为不健康
- 之所以改成 POST 而不是 GET，是因为 `/api/email/incoming` 只注册了 POST 处理器，
  旧版用 GET 探测时永远拿到 404，而 404 被旧逻辑误判为"健康"，鉴权失败等真实故障
  反而探测不出来

## 状态监控

访问 `http://mx.300031.xyz:8088/` 查看网关状态：
- **2: 连接成功** - 至少有一个健康的收件端
- **1: 未连接** - 没有健康的收件端

## DNS 配置

为了使邮件服务正常工作，需要配置以下 DNS 记录：

### MX 记录
```
@ MX 10 mx.300031.xyz.
```

### A 记录
```
mx.300031.xyz. A <服务器公网IP>
```

### SPF 记录（可选，推荐）
```
@ TXT "v=spf1 mx ~all"
```

## 端口要求

确保服务器防火墙开放以下端口：
- **25** - SMTP 邮件接收
- **8088** - HTTP 状态面板、注册/注销接口

## 邮件转发流程

1. 外部邮件服务器连接到网关的 25 端口，可能对同一封邮件执行多次 `RCPT TO`
   （群发到多个收件人）
2. 网关收集全部收件人地址（不会像旧版那样只保留最后一个）
3. 网关对邮件做 SPF / DKIM / DMARC 校验
4. 网关对**每个收件人 × 每个健康的收件端**分别发起一次转发请求，
   使用该收件端注册时提供的 `auth_token`
5. 收件端返回处理结果：
   - `200-299`: 该收件人接收成功
   - `404`: 该收件人不存在（网关会尝试其他收件端，不视为致命错误）
   - `401`/`403`: 密钥不匹配（会被下一轮健康检查发现并标记不健康）
   - 其他 `4xx`/`5xx`：投递失败，要求发件方重试
6. 只要有任意一个收件人被任意一个收件端接受，网关就向发件方返回成功；
   全部收件人在所有收件端都被判定 404，才向发件方返回 550 退信

## 开发

### 本地构建

```bash
git clone <this-repo>
cd mail
docker build -t email-forwarder .
docker run -d -p 25:25 -p 8088:8088 email-forwarder
```

本地没有 Go 环境时，可以直接推送到 `main` 分支或开 PR，由 GitHub Actions 完成
`go build` 编译校验（见 `.github/workflows/docker-build.yml`）。

### 目录结构

```
.
├── main.go              # 主程序
├── go.mod               # Go 模块定义
├── go.sum               # 依赖校验和
├── Dockerfile           # Docker 构建文件
├── docker-compose.yml   # Docker Compose 配置
└── README.md            # 本文档
```

## 技术栈

- **Go 1.22** - 编程语言
- **github.com/emersion/go-smtp** - SMTP 服务器库
- **github.com/emersion/go-msgauth** - DKIM / DMARC 校验
- **blitiri.com.ar/go/spf** - SPF 校验
- **golang.org/x/crypto/acme/autocert** - 自动 TLS 证书管理

## License

MIT License

## 支持

如有问题，请提交 Issue。
