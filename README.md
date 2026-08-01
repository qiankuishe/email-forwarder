# Email Forwarder Gateway

基于 Go 的 SMTP 邮件转发网关，支持自动 TLS 证书管理和多收件端分发。

## 功能特性

- ✅ SMTP 服务器（端口 25）
- ✅ 自动申请和续期 Let's Encrypt TLS 证书
- ✅ 多收件端注册与健康检查
- ✅ 邮件并发分发到所有健康的收件端
- ✅ HTTP 状态面板和注册接口
- ✅ 持久化存储收件端配置

## 快速部署

### 使用 Docker（推荐）

```bash
docker run -d \
  --name email-forwarder \
  -p 25:25 \
  -p 80:80 \
  -v $(pwd)/certs:/app/certs \
  -v $(pwd)/endpoints.json:/app/endpoints.json \
  --restart unless-stopped \
  fujiwarashuken/email-forwarder:latest
```

### 使用 Docker Compose

```bash
# 下载 docker-compose.yml
wget https://raw.githubusercontent.com/qiankuishe/email-forwarder/main/docker-compose.yml

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

## 配置说明

### 核心配置

当前配置：
- **域名**: `mx.300031.xyz`
- **认证密钥**: `ceemail`
- **SMTP 端口**: 25
- **HTTP 端口**: 80

修改配置需要重新构建镜像或使用环境变量（未来版本支持）。

### 收件端注册

收件端需要向网关发送握手请求来注册：

```bash
curl -X POST https://mx.300031.xyz/register \
  -H "X-Email-Auth-Token: ceemail" \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://your-backend.com/api/email/incoming"}'
```

注册成功后，网关会将收到的邮件转发到注册的 webhook URL。

### 健康检查

网关每 15 秒会对所有注册的收件端发送健康检查请求（GET 请求）。如果收件端返回 5xx 错误或请求失败，该收件端会被标记为不健康，暂时不会接收邮件。

## 状态监控

访问 `http://mx.300031.xyz/` 查看网关状态：
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
- **80** - HTTP（用于 Let's Encrypt 证书验证和状态面板）

## 邮件转发流程

1. 外部邮件服务器连接到网关的 25 端口
2. 网关接收邮件内容
3. 网关并发转发邮件到所有健康的收件端 webhook
4. 收件端返回处理结果：
   - `200-299`: 接收成功
   - `404`: 收件人不存在（网关会尝试其他收件端）
   - 其他错误: 投递失败

## 开发

### 本地构建

```bash
# 克隆仓库
git clone https://github.com/qiankuishe/email-forwarder.git
cd email-forwarder

# 构建镜像
docker build -t email-forwarder .

# 运行
docker run -d -p 25:25 -p 80:80 email-forwarder
```

### 目录结构

```
.
├── main.go              # 主程序
├── go.mod              # Go 模块定义
├── go.sum              # 依赖校验和
├── Dockerfile          # Docker 构建文件
├── docker-compose.yml  # Docker Compose 配置
└── README.md           # 本文档
```

## 技术栈

- **Go 1.22** - 编程语言
- **github.com/emersion/go-smtp** - SMTP 服务器库
- **golang.org/x/crypto/acme/autocert** - 自动 TLS 证书管理

## License

MIT License

## 支持

如有问题，请提交 Issue：
https://github.com/qiankuishe/email-forwarder/issues
