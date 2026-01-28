# Keycloak Proxy for AnythingLLM

A minimal setup to run AnythingLLM via Docker and front it with a Node-based reverse proxy that will later receive Keycloak/OIDC enforcement.

## Prerequisites
- Docker and Docker Compose installed
- Ports `3001` (AnythingLLM) and `8080` (proxy) free on your host

## Quick start
1. Pull the latest image (already done):
   ```powershell
   docker pull mintplexlabs/anythingllm:latest
   ```
2. Bring up the stack (from repo root):
   ```powershell
   docker compose up -d --build
   ```
3. Access AnythingLLM UI directly at http://localhost:3001 to complete first-time setup.
4. Use the proxy at http://localhost:8080 once configured; it currently forwards all traffic to AnythingLLM unchanged.

## Files
- `docker-compose.yml` — runs AnythingLLM and the proxy.
- `data/.env` — mounted into the AnythingLLM container. Update with your provider keys, secrets, etc.
- `proxy/` — simple Express reverse proxy ready for Keycloak hooks.

## Notes
- The proxy currently allows all requests; Keycloak validation middleware is stubbed and ready for realm details.
- Persistent storage lives in `./data` (mounted to `/app/server/storage`).