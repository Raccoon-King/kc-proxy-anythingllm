# Keycloak Proxy for AnythingLLM

A Go-based reverse proxy that fronts AnythingLLM with Keycloak OIDC authentication, manages sessions, and hands off to AnythingLLM using its Simple SSO token flow.

## Prerequisites
- Docker and Docker Compose
- Ports `3001` (AnythingLLM) and `8080` (proxy) free
- An AnythingLLM admin API key (for issuing user tokens)
- A Keycloak realm/client configured for standard Authorization Code flow

## Quick start
1) Export secrets (examples):
```powershell
$env:ANYLLM_API_KEY="your-admin-api-key"
$env:KEYCLOAK_ISSUER_URL="https://keycloak.example.com/realms/yourrealm"
$env:KEYCLOAK_CLIENT_ID="anythingllm-proxy"
$env:KEYCLOAK_CLIENT_SECRET="client-secret"
$env:SESSION_SECRET="long-random-string"
```
2) Bring up the stack:
```powershell
docker compose up -d --build
```
3) Visit http://localhost:8080. You will be redirected to Keycloak, then returned through the proxy which issues a Simple SSO token to AnythingLLM.

## Files
- `docker-compose.yml` — runs AnythingLLM and the Go proxy.
- `data/.env` — mounted into the AnythingLLM container (add provider keys, etc.).
- `go-proxy/` — Go reverse proxy with Keycloak login + Simple SSO handoff.

## AnythingLLM SSO note
Enable Simple SSO inside AnythingLLM by setting `SIMPLE_SSO_ENABLED=true` (see https://docs.anythingllm.com/configuration#simple-sso-passthrough). The proxy requests `/api/v1/users/{id}/issue-auth-token` and redirects to the returned `loginPath` so the browser receives the AnythingLLM session cookie.

## Environment (proxy)
- `PORT` (default `8080`)
- `ANYLLM_URL` (default `http://anythingllm:3001`)
- `ANYLLM_API_KEY` (required)
- `ANYLLM_AUTO_CREATE` (default `true`) — create users in AnythingLLM when missing.
- `ANYLLM_DEFAULT_ROLE` (default `user`)
- `KEYCLOAK_ISSUER_URL` (defaults to `http://keycloak:8080/realms/master` so it can talk to a Keycloak container on the same Docker network), `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`
- `KEYCLOAK_REDIRECT_URL` (default `http://localhost:8080/auth/callback`)
- `SESSION_SECRET` (required), `SESSION_SECURE` (`true` to force secure cookies)
- `BANNER_TOP_TEXT`, `BANNER_BOTTOM_TEXT` (default `SITE UNDER TEST`)
- `BANNER_BG_COLOR` (default `#f6f000`), `BANNER_TEXT_COLOR` (default `#000000`)
- `AGREEMENT_TITLE`, `AGREEMENT_BODY`, `AGREEMENT_BUTTON_TEXT` (configurable user agreement content)
- `KEYCLOAK_CA_PATH` (optional PEM bundle if Keycloak uses custom TLS), `KEYCLOAK_INSECURE_SKIP_VERIFY` (`true` to skip TLS verify for self-signed/dev)

## Login flow
1. User hits proxy → if no session, redirected to Keycloak.
2. Callback exchanges code, verifies ID token, ensures user exists in AnythingLLM (best-effort via API), and calls `issue-auth-token`.
3. User must accept the agreement (proxy enforced).
4. Browser is redirected through the proxy to AnythingLLM `loginPath`, establishing the upstream session.

## Development
- Build/test proxy locally:
  ```powershell
  cd go-proxy
  go test ./...
  go run ./cmd/server
  ```
- Proxy binary is built via multi-stage `go-proxy/Dockerfile` in Compose.
