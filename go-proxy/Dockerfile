# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/anythingllm-proxy ./cmd/server

FROM alpine:3.21
WORKDIR /app
COPY --from=build /bin/anythingllm-proxy /usr/local/bin/anythingllm-proxy
COPY config/default.env /app/config/default.env
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["entrypoint.sh"]
