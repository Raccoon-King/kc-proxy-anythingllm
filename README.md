# Keycloak Proxy for AnythingLLM

A Go reverse proxy that:
- Authenticates users with Keycloak (OIDC Authorization Code + PKCE).
- Mirrors/logs out stale sessions, including KC logout on state mismatch.
- Issues AnythingLLM Simple SSO tokens via the admin API and redirects to the returned `loginPath`.
- Injects mandatory banners and (optionally) a user-agreement gate.

## Documentation
- AnythingLLM product docs: https://docs.anythingllm.com/
- Keycloak local setup details: `../kecloak/README.md` (realm `mapache`, client `mapache-client`).
- Airgapped install: `docs/AIRGAPPED_INSTALL.md`.
- Production readiness checklist: `docs/PRODUCTION_READINESS.md`.
- Production values example: `docs/values.prod.example.yaml`.
- Restricted-namespace values example: `docs/values.restricted.example.yaml`.

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
$env:ANYLLM_API_KEY="CHANGE_ME"   # example
$env:KEYCLOAK_ISSUER_URL="http://localhost:8180/realms/mapache"
$env:KEYCLOAK_CLIENT_ID="mapache-client"
$env:KEYCLOAK_CLIENT_SECRET="CHANGE_ME"
$env:SESSION_SECRET="generate-a-random-string"
docker compose up -d --build
```
Browse to http://localhost:8080 and log in.

## Local Keycloak setup
- From `../kecloak`, run `docker compose up -d` to start Keycloak (image `quay.io/keycloak/keycloak:26.5.2`). Admin console: http://localhost:8180 (set your own admin credentials in the Keycloak setup).
- Realm: `mapache`; client: `mapache-client` (confidential OIDC). Allowed redirects include `http://localhost/*` and `http://127.0.0.1/*`; adjust in `config/realm-export.json` if needed.
- Seeded users: `admin`, `user`, `non-user` (set their passwords in your Keycloak setup). Realm role `app-user` is granted to `admin` and `user`.
- OIDC endpoints: issuer `http://localhost:8180/realms/mapache`, auth `/protocol/openid-connect/auth`, token `/token`, JWKS `/certs`. Client secret for dev: set in your Keycloak client configuration.

## Configuration (proxy)
- Core: `PORT` (8080), `APP_ENV` (development), `ANYLLM_URL` (http://anythingllm:3001), `ANYLLM_API_KEY` (required), `ANYLLM_AUTO_CREATE` (default true), `ANYLLM_DEFAULT_ROLE` (user)
- Keycloak: `KEYCLOAK_ISSUER_URL`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`, `KEYCLOAK_REDIRECT_URL` (default http://localhost:8080/auth/callback), `KEYCLOAK_CA_PATH`, `KEYCLOAK_INSECURE_SKIP_VERIFY`
  - Use `KEYCLOAK_EXTERNAL_URL` for the browser-facing realm URL (e.g., `http://localhost:8180/realms/mapache`); otherwise the proxy may redirect to the internal hostname (e.g., `http://keycloak:8080/`).
- Sessions/UI: `SESSION_SECRET` (required), `SESSION_SECURE` (false for http dev), `SESSION_SAMESITE` (lax/strict/none), `SESSION_MAX_AGE_DAYS` (7), `SESSION_HTTP_ONLY` (true)
- Banners: `BANNER_TOP_TEXT`, `BANNER_BOTTOM_TEXT`, `BANNER_BG_COLOR`, `BANNER_TEXT_COLOR`
- Agreement (can be disabled): `AGREEMENT_TITLE`, `AGREEMENT_BODY`, `AGREEMENT_BUTTON_TEXT`, `DISABLE_AGREEMENT` (default false)
- Logging/metrics: `ACCESS_LOGGING` (true), `DEBUG_LOGGING` (false), `SECURITY_LOGGING` (true), `DEBUG_HTTP` (true to log upstream calls), `METRICS_ENABLED` (false)
- Readiness: `READINESS_CHECKS` (false), `READINESS_URL` (required if enabled), `READINESS_TIMEOUT` (2s)
- Security headers: `SECURITY_HEADERS` (true), `HEADER_FRAME_OPTIONS`, `HEADER_REFERRER_POLICY`, `HEADER_PERMISSIONS`, `HEADER_CSP`
- Rate limiting: `RATE_LIMIT_PER_MIN` (0 disables), `RATE_LIMIT_BURST` (0)
- Timeouts/retries: `READ_TIMEOUT`, `WRITE_TIMEOUT`, `READ_HEADER_TIMEOUT`, `IDLE_TIMEOUT`, `SHUTDOWN_TIMEOUT`, `MAX_HEADER_BYTES`,
  `UPSTREAM_DIAL_TIMEOUT`, `UPSTREAM_TLS_HANDSHAKE_TIMEOUT`, `UPSTREAM_RESPONSE_HEADER_TIMEOUT`, `UPSTREAM_IDLE_TIMEOUT`,
  `UPSTREAM_MAX_IDLE_CONNS`, `UPSTREAM_MAX_IDLE_CONNS_PER_HOST`, `ANYLLM_HTTP_TIMEOUT`, `ANYLLM_RETRY_MAX`, `ANYLLM_RETRY_BACKOFF`

### Environment variables (proxy)
| Name | Default | Notes |
| --- | --- | --- |
| `ANYLLM_API_KEY` | _required_ | AnythingLLM admin API key for Simple SSO token issuance. |
| `ANYLLM_URL` | `http://anythingllm:3001` | Base URL for proxy→AnythingLLM calls. |
| `ANYLLM_AUTO_CREATE` | `true` | Auto-create users in AnythingLLM if missing. |
| `ANYLLM_DEFAULT_ROLE` | `user` | Default role on auto-create. |
| `APP_ENV` | `development` | Set to `production` to enforce stricter validation. |
| `KEYCLOAK_ISSUER_URL` | _required_ | Internal URL for proxy→Keycloak (matches realm issuer). |
| `KEYCLOAK_EXTERNAL_URL` | issuer | Public URL for browser redirects if different from issuer. |
| `KEYCLOAK_CLIENT_ID` | _required_ | Client configured in Keycloak (e.g., `mapache-client`). |
| `KEYCLOAK_CLIENT_SECRET` | _required_ | Dev secret provided by the Keycloak client. |
| `KEYCLOAK_REDIRECT_URL` | `http://localhost:8080/auth/callback` | Must be allowed in Keycloak client redirects. |
| `SESSION_SECRET` | _required_ | HMAC key for `anythingllm_proxy` session cookie. |
| `SESSION_SECURE` | `false` | Set `true` in HTTPS deployments. |
| `SESSION_SAMESITE` | `lax` | `lax`, `strict`, or `none` (`none` requires `SESSION_SECURE=true`). |
| `SESSION_MAX_AGE_DAYS` | `7` | Session cookie max age. |
| `SESSION_HTTP_ONLY` | `true` | Enforce HttpOnly on session cookie. |
| `BANNER_*`, `AGREEMENT_*` | defaults shown above | Optional UI banners and agreement gate. |
| `ACCESS_LOGGING` | `true` | Log request access lines. |
| `DEBUG_LOGGING` | `false` | Set `true` for verbose proxy logs. |
| `KEYCLOAK_CA_PATH` | _empty_ | PEM bundle for Keycloak TLS; use with `KEYCLOAK_INSECURE_SKIP_VERIFY=false`. |
| `METRICS_ENABLED` | `false` | Enable `/metrics` endpoint. |
| `READINESS_CHECKS` | `false` | Enable `/readyz` checks. |
| `READINESS_URL` | _empty_ | URL to check when readiness is enabled. |
| `RATE_LIMIT_PER_MIN` | `0` | Per-IP request limit per minute (0 disables). |
| `RATE_LIMIT_BURST` | `0` | Extra burst allowed beyond per-minute limit. |
| `ANYLLM_HTTP_TIMEOUT` | `10s` | Timeout for AnythingLLM admin API calls. |
| `ANYLLM_RETRY_MAX` | `0` | Retry count for AnythingLLM GET calls. |
| `ANYLLM_RETRY_BACKOFF` | `200ms` | Initial retry backoff for AnythingLLM GET calls. |

## AnythingLLM settings
Create `data/.env` (mounted to `/app/server/.env` inside the container) with at least:
```
SIMPLE_SSO_ENABLED=true
SIMPLE_SSO_NO_LOGIN=true   # optional if you only use SSO
```
See AnythingLLM docs for additional keys: https://docs.anythingllm.com/

## Flows & edge handling
- Missing/invalid SSO token on `/sso/*` → redirect to `/login` to restart.
- State mismatch in callback → clear proxy session + redirect to Keycloak RP logout, then restart.
- AnythingLLM 401/403 or login redirect → proxy clears its cookie and restarts login.
- Logged-in KC but logged-out AnythingLLM → caught by the above restart logic.

## Operational endpoints
- `GET /healthz` — liveness
- `GET /readyz` — readiness (optional, enable with `READINESS_CHECKS=true`)
- `GET /metrics` — Prometheus-style metrics (optional, enable with `METRICS_ENABLED=true`)

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

## Helm charts (Rancher + Argo)
Charts live under `helm/`:
- `helm/anythingllm`
- `helm/proxy`
- `helm/weaviate` (vendor dependency in `helm/weaviate/charts`)

By default charts install to the release namespace (set `namespace` in values to override).
Images should point to Harbor (set `image.registry` / `image.repository` / `image.tag` in each chart).
Proxy secrets are provided via `secretEnv` or `existingSecret`.
AnythingLLM secrets are provided via `secretEnv` or `existingSecret`.

Production hardening knobs (defaults are safe but off):
- `autoscaling`, `podDisruptionBudget`, and `networkPolicy` blocks in `values.yaml`.
- Security defaults: non-root, seccomp RuntimeDefault, and no SA token by default.

## Troubleshooting
- `ERR_TOO_MANY_REDIRECTS`: clear `anythingllm_proxy` cookie or hit `/logout`; stale state/codes will be bounced now.
- `failed to sync user`: check proxy logs for `[SEC] ensure user failed ...`; confirm ANYLLM_API_KEY is valid and Simple SSO is enabled.
- Keycloak code errors: ensure KC client has PKCE allowed, correct `KEYCLOAK_REDIRECT_URL`, and fresh authorization code (no reuse).

## Files
- `docker-compose.yml` — runs AnythingLLM + proxy.
- `data/.env` — AnythingLLM server config.
- `go-proxy/` — Go proxy sources and tests.
