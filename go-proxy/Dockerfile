# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/anythingllm-proxy ./cmd/server

FROM alpine:3.19
WORKDIR /app
COPY --from=build /bin/anythingllm-proxy /usr/local/bin/anythingllm-proxy
EXPOSE 8080
ENV PORT=8080
CMD ["anythingllm-proxy"]
