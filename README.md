# Keycloak Proxy for AnythingLLM

A Go reverse proxy that:
- Authenticates users with Keycloak (OIDC Authorization Code + PKCE).
- Mirrors/logs out stale sessions, including KC logout on state mismatch.
- Issues AnythingLLM Simple SSO tokens via the admin API and redirects to the returned `loginPath`.
- Injects mandatory banners and (optionally) a user-agreement gate.

## Architecture
```
Browser → Proxy (Go) → AnythingLLM (API & UI)
                ↘→ Keycloak (OIDC)
```
- Sessions are stored in a signed HTTP-only cookie `anythingllm_proxy`.
- On login: proxy exchanges the KC code, ensures the user exists (or creates), fetches `/api/v1/users/{id}/issue-auth-token`, and redirects to `/sso/simple?token=...`.
- If AnythingLLM returns 401/403 or a login redirect, the proxy clears its cookie and restarts login. State mismatches also trigger KC logout.

## Prerequisites
- Docker & Docker Compose
- Ports free: `3001` (AnythingLLM), `8080` (proxy)
- AnythingLLM admin API key
- Keycloak realm/client configured for Auth Code + client secret (PKCE allowed)

## Quick start
```powershell
$env:ANYLLM_API_KEY="XN6FD4N-26N4BXR-JXS1DT9-F2D8MHT"   # example
$env:KEYCLOAK_ISSUER_URL="http://localhost:8180/realms/mapache"
$env:KEYCLOAK_CLIENT_ID="mapache-client"
$env:KEYCLOAK_CLIENT_SECRET="7HMLGYoxhKIjmOQZkK9Bp1z3oamucLIc"
$env:SESSION_SECRET="generate-a-random-string"
docker compose up -d --build
```
Browse to http://localhost:8080 and log in.

## Configuration (proxy)
- Core: `PORT` (8080), `ANYLLM_URL` (http://anythingllm:3001), `ANYLLM_API_KEY` (required), `ANYLLM_AUTO_CREATE` (default true), `ANYLLM_DEFAULT_ROLE` (user)
- Keycloak: `KEYCLOAK_ISSUER_URL`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`, `KEYCLOAK_REDIRECT_URL` (default http://localhost:8080/auth/callback), `KEYCLOAK_CA_PATH`, `KEYCLOAK_INSECURE_SKIP_VERIFY`
- Sessions/UI: `SESSION_SECRET` (required), `SESSION_SECURE` (false for http dev)
- Banners: `BANNER_TOP_TEXT`, `BANNER_BOTTOM_TEXT`, `BANNER_BG_COLOR`, `BANNER_TEXT_COLOR`
- Agreement (can be disabled): `AGREEMENT_TITLE`, `AGREEMENT_BODY`, `AGREEMENT_BUTTON_TEXT`, `DISABLE_AGREEMENT` (default false)
- Logging: `DEBUG_LOGGING` (false), `SECURITY_LOGGING` (true), `DEBUG_HTTP` (true to log upstream calls)

## AnythingLLM settings
In `data/.env` (mounted to `/app/server/.env`):
```
SIMPLE_SSO_ENABLED=true
SIMPLE_SSO_NO_LOGIN=true   # optional if you only use SSO
```

## Flows & edge handling
- Missing/invalid SSO token on `/sso/*` → redirect to `/login` to restart.
- State mismatch in callback → clear proxy session + redirect to Keycloak RP logout, then restart.
- AnythingLLM 401/403 or login redirect → proxy clears its cookie and restarts login.
- Logged-in KC but logged-out AnythingLLM → caught by the above restart logic.

## Banners & agreement
- Banners are injected into every HTML response from AnythingLLM.
- Agreement gate is enabled by default; set `DISABLE_AGREEMENT=true` to skip (keeps tests passing with flag).

## Make a user login URL manually (admin)
```
curl -H "Authorization: Bearer $ANYLLM_API_KEY" \
  http://localhost:3001/api/v1/users/1/issue-auth-token
# → {"token":"...","loginPath":"/sso/simple?token=..."}
```
Redirect the browser to `http://localhost:3001/loginPath` (add `&redirectTo=/path` if desired).

## Development
```powershell
cd go-proxy
go test ./...
go run ./cmd/server   # uses env vars
```
Docker builds via `go-proxy/Dockerfile`; `docker compose up -d --build` to rebuild the proxy container.

## Troubleshooting
- `ERR_TOO_MANY_REDIRECTS`: clear `anythingllm_proxy` cookie or hit `/logout`; stale state/codes will be bounced now.
- `failed to sync user`: check proxy logs for `[SEC] ensure user failed ...`; confirm ANYLLM_API_KEY is valid and Simple SSO is enabled.
- Keycloak code errors: ensure KC client has PKCE allowed, correct `KEYCLOAK_REDIRECT_URL`, and fresh authorization code (no reuse).

## Files
- `docker-compose.yml` — runs AnythingLLM + proxy.
- `data/.env` — AnythingLLM server config.
- `go-proxy/` — Go proxy sources and tests.
