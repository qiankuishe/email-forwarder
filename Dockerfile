FROM golang:1.22-alpine AS builder

WORKDIR /app

# 1. 复制依赖描述文件
COPY go.mod ./

# 2. 拉取依赖
RUN go mod tidy

# 3. 复制源代码
COPY . .

# 4. 编译二进制文件
RUN rm -f go.sum && go clean -modcache && go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o mail-gateway .
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
