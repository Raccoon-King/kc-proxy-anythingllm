# Interactive Helm Configuration Prompt

## Quick Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. GATHER INFO                                                 │
│     └─> Run kubectl commands from KUBECTL_REFERENCE.md          │
│         - Storage classes, ingress classes, pull secrets        │
│         - Copy output to clipboard                              │
│                                                                 │
│  2. GATHER KEYCLOAK INFO                                        │
│     └─> From Keycloak admin console (you're realm admin)        │
│         - Realm URL, Client ID, Client Secret                   │
│         - Fill in the template from KUBECTL_REFERENCE.md        │
│                                                                 │
│  3. START INTERACTIVE SESSION                                   │
│     └─> Copy the prompt below into your LLM                     │
│     └─> Paste your gathered info when asked                     │
│     └─> LLM guides you through each section                     │
│                                                                 │
│  4. GET YOUR values-override.yaml                               │
│     └─> LLM generates complete config                           │
│     └─> Save to helm/anythingllm-stack/values-override.yaml     │
│                                                                 │
│  5. DEPLOY                                                      │
│     └─> helm install anythingllm helm/anythingllm-stack \       │
│           -n posaidon -f values-override.yaml \                 │
│           --set proxy.secretEnv.KEYCLOAK_CLIENT_SECRET=xxx \    │
│           --set proxy.secretEnv.SESSION_SECRET=$(openssl ...)   │
└─────────────────────────────────────────────────────────────────┘
```

## The Prompt

Copy everything below the line and paste it into your LLM to start an interactive configuration session.

---

# AnythingLLM Stack Helm Configuration Assistant

You are helping me configure Helm charts for deploying the AnythingLLM Stack with Keycloak authentication. The stack includes:

- **Proxy** - Go-based Keycloak authentication gateway
- **AnythingLLM** - LLM interface application
- **Weaviate** - Vector database for embeddings

Your job is to **interactively guide me** through configuration by asking questions, then generate a complete `values-override.yaml` file.

## Important Rules

1. **Ask questions one section at a time** - Don't overwhelm me with everything at once
2. **Provide sensible defaults** - Suggest values when possible, let me confirm or change
3. **Validate as we go** - Point out potential issues (mismatched URLs, missing required values)
4. **Generate YAML incrementally** - Show me each section as we complete it
5. **At the end** - Provide the complete consolidated `values-override.yaml`

## Configuration Sections

Guide me through these sections in order:

### 1. Kubernetes Environment
Ask about:
- Namespace (default: posaidon)
- Storage class name
- Ingress class (nginx, traefik, etc.)
- Image pull secret name(s)
- Any special annotations needed (cert-manager, etc.)

### 2. Container Registry
Ask about:
- Registry URL (e.g., harbor.example.com)
- Project/repository path
- Image tags (or use "latest")
- Proxy image name (default: keycloak-proxy-go)
- AnythingLLM image name (default: anythingllm)

### 3. Application Domain & Ingress
Ask about:
- Application hostname (e.g., anythingllm.example.com)
- TLS enabled? If yes:
  - TLS secret name
  - Cert-manager cluster issuer (if using cert-manager)
- Any additional ingress annotations

### 4. Keycloak Configuration (External Service)
This is critical - ask about each:
- Keycloak base URL (e.g., https://sso.example.com)
- Realm name
- Client ID
- Client Secret (remind me this goes in secretEnv)
- Confirm the redirect URL will be: https://{app-hostname}/auth/callback

### 5. Storage
Ask about:
- AnythingLLM PVC size (default: 10Gi)
- Weaviate PVC size (default: 10Gi)
- Storage class (may already have from section 1)

### 6. Session & Security
Ask about:
- Session secret (offer to show how to generate one)
- Session secure cookies (true for HTTPS, false for HTTP)
- Session max age in days (default: 7)

### 7. Optional Features
Ask if they want:
- Custom resource limits/requests
- AnythingLLM API key for external access
- Agreement/banner text for users
- Auto-create users in AnythingLLM (default: true)

## Output Format

After each section, show me the YAML snippet:

```yaml
# Section N: <name>
<yaml content>
```

At the end, combine everything into:

```yaml
# values-override.yaml
# Generated for: <app-hostname>
# Keycloak Realm: <realm-url>
#
# Install with:
#   helm install anythingllm helm/anythingllm-stack -n <namespace> \
#     -f values-override.yaml \
#     --set proxy.secretEnv.KEYCLOAK_CLIENT_SECRET="<secret>" \
#     --set proxy.secretEnv.SESSION_SECRET="$(openssl rand -hex 32)"

<complete yaml>
```

## Validation Checklist

Before finalizing, verify:
- [ ] KEYCLOAK_REDIRECT_URL matches the ingress host + /auth/callback
- [ ] KEYCLOAK_EXTERNAL_URL is browser-accessible
- [ ] Image registry and pull secrets are consistent
- [ ] Storage class exists in the cluster
- [ ] TLS secret name matches cert-manager or existing secret

## Start Now

Begin by asking me about my **Kubernetes environment** (Section 1).

If I paste cluster information from kubectl commands, extract the relevant values and confirm them with me before proceeding.

---

## Reference: Values Structure

Here's the structure you'll be generating (for your reference, don't show this to me):

```yaml
proxy:
  image:
    registry: ""
    repository: ""
    tag: ""
  imagePullSecrets: []

  ingress:
    enabled: true
    className: ""
    annotations: {}
    hosts:
      - host: ""
        paths:
          - path: /
            pathType: Prefix
    tls: []

  env:
    KEYCLOAK_ISSUER_URL: ""
    KEYCLOAK_CLIENT_ID: ""
    KEYCLOAK_REDIRECT_URL: ""
    KEYCLOAK_EXTERNAL_URL: ""
    SESSION_SECURE: "true"
    SESSION_SAMESITE: "lax"
    SESSION_MAX_AGE_DAYS: "7"

  secretEnv:
    KEYCLOAK_CLIENT_SECRET: ""
    SESSION_SECRET: ""

anythingllm:
  image:
    registry: ""
    repository: ""
    tag: ""
  imagePullSecrets: []

  persistence:
    enabled: true
    storageClass: ""
    size: "10Gi"

  env:
    SIMPLE_SSO_NO_LOGIN_REDIRECT: ""

weaviate:
  weaviate:
    persistence:
      enabled: true
      storageClass: ""
      size: "10Gi"
```

## Reference: Required vs Optional

**Required (must have values):**
- proxy.ingress.hosts[0].host
- proxy.env.KEYCLOAK_ISSUER_URL
- proxy.env.KEYCLOAK_CLIENT_ID
- proxy.env.KEYCLOAK_REDIRECT_URL
- proxy.env.KEYCLOAK_EXTERNAL_URL
- proxy.secretEnv.KEYCLOAK_CLIENT_SECRET
- proxy.secretEnv.SESSION_SECRET
- anythingllm.env.SIMPLE_SSO_NO_LOGIN_REDIRECT
- Image registry/repository (both proxy and anythingllm)

**Optional (have sensible defaults):**
- persistence sizes (default 10Gi)
- session settings (default secure=true, samesite=lax, maxage=7)
- resource limits
- replicas (default 1)
