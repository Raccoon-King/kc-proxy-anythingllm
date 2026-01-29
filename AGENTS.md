# Repository Guidelines

## Project Structure & Modules
- `go-proxy/`: Go reverse proxy (primary). `cmd/server` holds the entrypoint; `internal/{auth,config,server,anythingllm}` contain auth flow, configuration, router, and AnythingLLM client logic. Tests live alongside source files.
- `proxy/`: Legacy Node prototype (Express). Not used in Compose but kept for reference; its `npm test` is a stub.
- `data/`: Volume mount for AnythingLLM (`data/.env` copied into the container). `docker-compose.yml` builds the Go proxy and runs AnythingLLM.

## Build, Test, and Development Commands
- `cd go-proxy && go test ./...`: Run Go unit tests (fast, no network calls).
- `cd go-proxy && go run ./cmd/server`: Start the proxy locally using current env vars.
- `docker compose up -d --build`: Build and start AnythingLLM + Go proxy with the configured environment.

## Coding Style & Naming Conventions
- Go 1.24; format with `gofmt` (tabs, standard Go imports). Keep package names lowercase and short (e.g., `auth`, `server`).
- Prefer clear function names mirroring behavior (`NewOIDCAdapter...`, `EnsureUser`); exported types need doc comments.
- Return errors (no panics) and log with `log.Printf`/`log.Fatalf` for fatal setup issues only. Avoid inline comments except for lint suppressions.

## Testing Guidelines
- Use `go test ./...` before pushing; table-driven tests are preferred. Keep tests near implementations (e.g., `cmd/server/main_test.go`).
- Inject dependencies (see `runFn`, `serve`, `newOIDC` stubs in tests) to avoid network calls; set `SKIP_LISTEN=true` when you need config without binding a port.

## Commit & Pull Request Guidelines
- Follow the existing Conventional Commit style (`feat: ...`, `fix: ...`). Keep messages imperative and scoped.
- PRs should describe behavior changes, include repro steps or env vars if relevant, and note test coverage (`go test ./...`). Add screenshots only when UI responses (banners/agreement) change.

## Security & Configuration Tips
- Never commit real secrets. Required env vars: `ANYLLM_API_KEY`, `KEYCLOAK_ISSUER_URL`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`, `SESSION_SECRET`; defaults exist for local dev only.
- `data/.env` is mounted into AnythingLLM; enable `SIMPLE_SSO_ENABLED=true` and `SIMPLE_SSO_NO_LOGIN=true` for proxy-driven auth.
- For TLS to Keycloak, set `KEYCLOAK_CA_PATH` or `KEYCLOAK_INSECURE_SKIP_VERIFY=true` (dev only). Use `KEYCLOAK_EXTERNAL_URL` when the browser must reach Keycloak via a different host.
