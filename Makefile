.PHONY: test run fmt compose-up compose-down smoke

test:
	cd go-proxy && go test ./...

run:
	cd go-proxy && go run ./cmd/server

fmt:
	cd go-proxy && gofmt -w ./

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

smoke:
	sh ./scripts/smoke.sh
