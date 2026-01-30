# Documentation Index

## Deployment Guides

| Document | Purpose |
|----------|---------|
| [HELM_INSTALL_GUIDE.md](HELM_INSTALL_GUIDE.md) | Complete Helm installation walkthrough |
| [KUBECTL_REFERENCE.md](KUBECTL_REFERENCE.md) | Commands to extract cluster config for LLM |
| [INTERACTIVE_CONFIG_PROMPT.md](INTERACTIVE_CONFIG_PROMPT.md) | Prompt for LLM to help build your values file |
| [AIRGAPPED_INSTALL.md](AIRGAPPED_INSTALL.md) | Installation without internet access |

## Other Documentation

| Document | Purpose |
|----------|---------|
| [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) | Production deployment checklist |
| [LOCAL_CICD.md](LOCAL_CICD.md) | Local CI/CD setup guide |

---

## Quick Start: LLM-Assisted Configuration

### Step 1: Gather Kubernetes Info

Run the export script from [KUBECTL_REFERENCE.md](KUBECTL_REFERENCE.md):

```bash
NAMESPACE=posaidon
{
  echo "=== STORAGE CLASSES ===" && kubectl get storageclass -o wide
  echo "=== INGRESS CLASSES ===" && kubectl get ingressclass -o wide
  echo "=== IMAGE PULL SECRETS ===" && kubectl get secrets -n $NAMESPACE | grep -E 'docker|registry'
  echo "=== EXISTING INGRESSES ===" && kubectl get ingress -n $NAMESPACE -o yaml | grep -A10 annotations
} > cluster-info.txt
```

### Step 2: Gather Keycloak Info

From Keycloak admin console (you're realm admin):
- Keycloak URL: `https://sso.example.com/realms/myrealm`
- Client ID: `anythingllm`
- Client Secret: (from Credentials tab)

### Step 3: Start Interactive LLM Session

1. Copy the entire prompt from [INTERACTIVE_CONFIG_PROMPT.md](INTERACTIVE_CONFIG_PROMPT.md)
2. Paste into your LLM
3. When asked, paste your `cluster-info.txt` and Keycloak details
4. LLM will guide you through each section
5. Save the generated `values-override.yaml`

### Step 4: Deploy

```bash
cd helm/anythingllm-stack
helm dependency update

helm install anythingllm . -n posaidon \
  -f values-override.yaml \
  --set proxy.secretEnv.KEYCLOAK_CLIENT_SECRET="your-secret" \
  --set proxy.secretEnv.SESSION_SECRET="$(openssl rand -hex 32)"
```

---

## File Locations

```
keycloak-proxy-anythingllm/
├── docs/
│   ├── README.md                    # This file
│   ├── HELM_INSTALL_GUIDE.md        # Manual installation guide
│   ├── KUBECTL_REFERENCE.md         # Kubectl commands for config extraction
│   ├── INTERACTIVE_CONFIG_PROMPT.md # LLM prompt for interactive config
│   ├── AIRGAPPED_INSTALL.md         # Offline installation
│   ├── PRODUCTION_READINESS.md      # Production checklist
│   └── LOCAL_CICD.md                # CI/CD setup
├── helm/
│   ├── anythingllm-stack/           # Umbrella chart (install this)
│   ├── proxy/                       # Proxy subchart
│   ├── anythingllm/                 # AnythingLLM subchart
│   ├── weaviate/                    # Weaviate subchart
│   └── prompt.md                    # One-shot LLM config prompt
└── go-proxy/                        # Go proxy source code
```
