# Go 1.22 已停止维护，标准库（crypto/tls、net/http、net/mail 等）有多个已公开漏洞，
# 用仍在维护的 1.26 系列构建。
FROM golang:1.26-alpine AS builder

WORKDIR /app

# 1. 复制依赖描述文件（含 go.sum，用于校验依赖完整性）
COPY go.mod go.sum ./

# 2. 按 go.sum 下载依赖。
#    这里不能用 `rm -f go.sum && go mod tidy`——那样每次构建都重新解析依赖，
#    go.sum 的供应链校验形同虚设，而且会掩盖 go.sum 本身损坏的问题。
#    依赖有变动时，在本地跑 `go mod tidy` 并提交更新后的 go.mod / go.sum。
RUN go mod download

# 3. 复制源代码
COPY . .

# 4. 编译：去掉本机路径与调试符号
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o mail-gateway .

# 运行镜像
FROM alpine:3

# 安装证书以支持 TLS 请求
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# 从构建器中复制二进制文件
COPY --from=builder /app/mail-gateway .

# 说明：仍以容器内 root 运行，是为了兼容已有部署里宿主机 root 所有的
# ./endpoints.json 与 ./certs（换成非 root 用户会写不进去，注册信息丢失）。
# 权限收敛放在 docker-compose.yml：cap_drop ALL、只读根文件系统、no-new-privileges。

# 暴露端口 (25: SMTP, 8088: HTTP 状态面板及注册接口)
EXPOSE 25 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 25 || exit 1

# 运行程序
CMD ["./mail-gateway"]
