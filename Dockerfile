FROM golang:1.22-alpine AS builder

WORKDIR /app

# 1. 复制依赖描述文件（含 go.sum，用于校验依赖完整性）
COPY go.mod go.sum ./

# 2. 按 go.sum 下载依赖。
#    这里不能用 `rm -f go.sum && go mod tidy`——那样每次构建都重新解析依赖，
#    go.sum 的供应链校验形同虚设，而且会掩盖 go.sum 本身损坏的问题
#    （本仓库曾出现 go.sum 缺条目且哈希错误，本地 go build 一直失败，
#    只有 Docker 构建"能过"，因为它把 go.sum 删了）。
#    依赖有变动时，在本地跑 `go mod tidy` 并提交更新后的 go.mod / go.sum。
RUN go mod download

# 3. 复制源代码
COPY . .

# 4. 编译二进制文件
RUN CGO_ENABLED=0 GOOS=linux go build -o mail-gateway .
# 运行镜像
FROM alpine:latest

# 安装证书以支持 TLS 请求
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# 从构建器中复制二进制文件
COPY --from=builder /app/mail-gateway .

# 暴露端口 (25: SMTP, 8088: HTTP 状态面板及注册接口)
EXPOSE 25 8088

# 运行程序
CMD ["./mail-gateway"]
