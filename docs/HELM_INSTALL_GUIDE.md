# AnythingLLM Stack Helm Installation Guide

This guide walks you through deploying the AnythingLLM Stack using Helm.

## Components

The stack includes:
- **Proxy** - Keycloak authentication gateway
- **AnythingLLM** - LLM interface application
- **Weaviate** - Vector database for embeddings

## Prerequisites

- Kubernetes cluster (1.23+)
- Helm 3.10+
- `kubectl` configured for your cluster
- Ingress controller (nginx, traefik, etc.)
- Keycloak instance with a configured client

## Quick Start

```bash
# Clone the repository
git clone <repo-url>
cd keycloak-proxy-anythingllm

# Update dependencies
cd helm/anythingllm-stack
helm dependency update

# Install (replace values with your configuration)
helm install anythingllm . -n mynamespace \
  --set proxy.image.registry=myregistry.com \
  --set proxy.image.repository=myrepo/keycloak-proxy-go \
  --set anythingllm.image.registry=myregistry.com \
  --set anythingllm.image.repository=myrepo/anythingllm \
  --set proxy.ingress.className=nginx \
  --set proxy.ingress.hosts[0].host=app.example.com \
  --set proxy.env.KEYCLOAK_ISSUER_URL=https://keycloak.example.com/realms/myrealm \
  --set proxy.env.KEYCLOAK_CLIENT_ID=my-client \
  --set proxy.env.KEYCLOAK_REDIRECT_URL=https://app.example.com/auth/callback \
  --set proxy.env.KEYCLOAK_EXTERNAL_URL=https://keycloak.example.com/realms/myrealm \
  --set anythingllm.env.SIMPLE_SSO_NO_LOGIN_REDIRECT=https://app.example.com/login \
  --set proxy.secretEnv.KEYCLOAK_CLIENT_SECRET=your-client-secret \
  --set proxy.secretEnv.SESSION_SECRET=$(openssl rand -hex 32)
```

## Step-by-Step Installation

### Step 1: Prepare Your Values File

Create a `values-override.yaml` file:

```yaml
# values-override.yaml

proxy:
  image:
    registry: myregistry.com
    repository: myrepo/keycloak-proxy-go
    tag: latest

  imagePullSecrets:
    - my-registry-secret

  ingress:
    enabled: true
    className: nginx  # or traefik, istio, etc.
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    hosts:
      - host: app.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: app-tls
        hosts:
          - app.example.com

  env:
    # Keycloak Configuration (REQUIRED)
    KEYCLOAK_ISSUER_URL: "https://keycloak.example.com/realms/myrealm"
    KEYCLOAK_CLIENT_ID: "my-client"
    KEYCLOAK_REDIRECT_URL: "https://app.example.com/auth/callback"
    KEYCLOAK_EXTERNAL_URL: "https://keycloak.example.com/realms/myrealm"

    # Session settings for HTTPS
    SESSION_SECURE: "true"
    SESSION_SAMESITE: "lax"

  secretEnv:
    KEYCLOAK_CLIENT_SECRET: ""  # Set via --set or external secret
    SESSION_SECRET: ""          # Set via --set or external secret

anythingllm:
  image:
    registry: myregistry.com
    repository: myrepo/anythingllm
    tag: latest

  imagePullSecrets:
    - my-registry-secret

  persistence:
    storageClass: standard  # Your storage class
    size: 20Gi

  env:
    SIMPLE_SSO_NO_LOGIN_REDIRECT: "https://app.example.com/login"

weaviate:
  weaviate:
    persistence:
      storageClass: standard
      size: 20Gi
```

### Step 2: Configure Keycloak

In your Keycloak admin console:

1. Create a new client (or use existing)
2. Set **Client Protocol** to `openid-connect`
3. Set **Access Type** to `confidential`
4. Add **Valid Redirect URIs**: `https://app.example.com/auth/callback`
5. Add **Web Origins**: `https://app.example.com`
6. Enable **Standard Flow**
7. Copy the **Client Secret** from the Credentials tab

### Step 3: Generate Secrets

```bash
# Generate a random session secret
export SESSION_SECRET=$(openssl rand -hex 32)
echo "SESSION_SECRET: $SESSION_SECRET"

# Get your Keycloak client secret from Keycloak admin console
export KEYCLOAK_CLIENT_SECRET="your-client-secret-from-keycloak"
```

### Step 4: Install the Chart

```bash
cd helm/anythingllm-stack
helm dependency update

helm install anythingllm . -n mynamespace \
  -f values-override.yaml \
  --set proxy.secretEnv.KEYCLOAK_CLIENT_SECRET=$KEYCLOAK_CLIENT_SECRET \
  --set proxy.secretEnv.SESSION_SECRET=$SESSION_SECRET
```

### Step 5: Verify Installation

```bash
# Check pod status
kubectl get pods -n mynamespace -l app.kubernetes.io/instance=anythingllm

# Watch pods come up
kubectl get pods -n mynamespace -w

# Check init containers (dependency ordering)
kubectl logs -n mynamespace deploy/proxy -c wait-for-anythingllm
kubectl logs -n mynamespace deploy/anythingllm -c wait-for-weaviate

# Check application logs
kubectl logs -n mynamespace deploy/proxy
kubectl logs -n mynamespace deploy/anythingllm
kubectl logs -n mynamespace sts/weaviate
```

### Step 6: Access the Application

Once all pods are running:
```bash
# Get the ingress URL
kubectl get ingress -n mynamespace

# Or port-forward for testing
kubectl port-forward -n mynamespace svc/proxy 8080:8080
```

Visit `https://app.example.com` (or `http://localhost:8080` if port-forwarding).

## Configuration Reference

### Required Configuration

| Parameter | Description | Example |
|-----------|-------------|---------|
| `proxy.ingress.hosts[0].host` | Ingress hostname | `app.example.com` |
| `proxy.env.KEYCLOAK_ISSUER_URL` | Internal Keycloak URL | `https://keycloak.example.com/realms/myrealm` |
| `proxy.env.KEYCLOAK_CLIENT_ID` | Keycloak client ID | `my-client` |
| `proxy.env.KEYCLOAK_REDIRECT_URL` | OAuth callback URL | `https://app.example.com/auth/callback` |
| `proxy.env.KEYCLOAK_EXTERNAL_URL` | Browser-accessible Keycloak URL | `https://keycloak.example.com/realms/myrealm` |
| `anythingllm.env.SIMPLE_SSO_NO_LOGIN_REDIRECT` | Login redirect URL | `https://app.example.com/login` |
| `proxy.secretEnv.KEYCLOAK_CLIENT_SECRET` | Keycloak client secret | (from Keycloak) |
| `proxy.secretEnv.SESSION_SECRET` | Session encryption key | (generate with openssl) |

### Image Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `proxy.image.registry` | Proxy image registry | `""` |
| `proxy.image.repository` | Proxy image repository | `""` |
| `proxy.image.tag` | Proxy image tag | `latest` |
| `proxy.imagePullSecrets` | Image pull secrets | `[]` |
| `anythingllm.image.registry` | AnythingLLM image registry | `""` |
| `anythingllm.image.repository` | AnythingLLM image repository | `""` |
| `anythingllm.image.tag` | AnythingLLM image tag | `latest` |
| `weaviate.weaviate.image.tag` | Weaviate image tag | `1.34.0` |

### Storage Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `anythingllm.persistence.enabled` | Enable persistence | `true` |
| `anythingllm.persistence.storageClass` | Storage class | `""` |
| `anythingllm.persistence.size` | PVC size | `10Gi` |
| `weaviate.weaviate.persistence.enabled` | Enable persistence | `true` |
| `weaviate.weaviate.persistence.storageClass` | Storage class | `""` |
| `weaviate.weaviate.persistence.size` | PVC size | `10Gi` |

### Session Configuration (HTTPS)

For HTTPS deployments:

```yaml
proxy:
  env:
    SESSION_SECURE: "true"      # Required for HTTPS
    SESSION_SAMESITE: "lax"     # Or "none" for cross-domain
    SESSION_MAX_AGE_DAYS: "7"
```

## Using Existing Secrets

Instead of passing secrets via `--set`, you can use pre-created Kubernetes secrets:

```bash
# Create secrets manually
kubectl create secret generic proxy-secrets -n mynamespace \
  --from-literal=KEYCLOAK_CLIENT_SECRET=your-secret \
  --from-literal=SESSION_SECRET=$(openssl rand -hex 32) \
  --from-literal=ANYLLM_API_KEY=optional-api-key
```

Then reference in values:
```yaml
proxy:
  existingSecret: proxy-secrets
```

## Upgrading

```bash
# Update dependencies
cd helm/anythingllm-stack
helm dependency update

# Upgrade release
helm upgrade anythingllm . -n mynamespace \
  -f values-override.yaml \
  --set proxy.secretEnv.KEYCLOAK_CLIENT_SECRET=$KEYCLOAK_CLIENT_SECRET \
  --set proxy.secretEnv.SESSION_SECRET=$SESSION_SECRET
```

**Note:** The JWT_SECRET for AnythingLLM is automatically preserved across upgrades.

## Uninstalling

```bash
helm uninstall anythingllm -n mynamespace

# Note: PVCs are not deleted automatically
kubectl delete pvc -n mynamespace -l app.kubernetes.io/instance=anythingllm
```

## Troubleshooting

### Pods Stuck in Init

Check init container logs:
```bash
kubectl logs -n mynamespace deploy/proxy -c wait-for-anythingllm
kubectl logs -n mynamespace deploy/anythingllm -c wait-for-weaviate
```

Common causes:
- Weaviate not starting (check `kubectl logs -n mynamespace sts/weaviate`)
- PVC not bound (check `kubectl get pvc -n mynamespace`)

### ERR_TOO_MANY_REDIRECTS

1. Clear browser cookies (especially `anythingllm_proxy`)
2. Visit `/logout` endpoint first
3. Check that `KEYCLOAK_REDIRECT_URL` matches your ingress host

### Authentication Failures

1. Verify Keycloak client configuration:
   - Valid redirect URIs include your callback URL
   - Client secret is correct
   - Client protocol is `openid-connect`

2. Check proxy logs:
   ```bash
   kubectl logs -n mynamespace deploy/proxy | grep -i error
   ```

3. Verify URLs match:
   - `KEYCLOAK_REDIRECT_URL` should match ingress host
   - `KEYCLOAK_EXTERNAL_URL` should be browser-accessible

### PVC Pending

```bash
kubectl describe pvc -n mynamespace

# Check if storage class exists
kubectl get storageclass
```

### Image Pull Errors

```bash
kubectl describe pod -n mynamespace <pod-name>

# Verify image pull secret
kubectl get secret -n mynamespace my-registry-secret
```

## Architecture

```
                    ┌─────────────────┐
                    │    Ingress      │
                    │  (nginx/traefik)│
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │     Proxy       │
                    │   (port 8080)   │
                    │                 │
                    │ - Keycloak Auth │
                    │ - Session Mgmt  │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   AnythingLLM   │
                    │   (port 3001)   │
                    │                 │
                    │ - LLM Interface │
                    │ - Simple SSO    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │    Weaviate     │
                    │    (port 80)    │
                    │                 │
                    │ - Vector DB     │
                    │ - Embeddings    │
                    └─────────────────┘
```

## Startup Order

The stack starts in order using init containers:

1. **Weaviate** starts first (no dependencies)
2. **AnythingLLM** waits for Weaviate (port 80), then starts
3. **Proxy** waits for AnythingLLM (port 3001), then starts

This ensures all services are ready before accepting traffic.
