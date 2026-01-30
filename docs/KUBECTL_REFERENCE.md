# Kubectl/Helm Reference Commands

Quick reference for extracting environment-specific configuration from your Rancher/Kubernetes cluster. Use the output to feed to an LLM with `helm/prompt.md` for chart configuration.

## Quick Export (All-in-One)

Run this to get most of what you need in one shot:

```bash
# Export everything useful to a single file
NAMESPACE=posaidon
{
  echo "=== NAMESPACE: $NAMESPACE ==="
  echo ""
  echo "=== STORAGE CLASSES ==="
  kubectl get storageclass -o wide
  echo ""
  echo "=== INGRESS CLASSES ==="
  kubectl get ingressclass -o wide 2>/dev/null || echo "No ingress classes found"
  echo ""
  echo "=== IMAGE PULL SECRETS ==="
  kubectl get secrets -n $NAMESPACE -o custom-columns='NAME:.metadata.name,TYPE:.type' | grep -E 'docker|registry'
  echo ""
  echo "=== PVCS ==="
  kubectl get pvc -n $NAMESPACE -o custom-columns='NAME:.metadata.name,STORAGE_CLASS:.spec.storageClassName,SIZE:.spec.resources.requests.storage,STATUS:.status.phase'
  echo ""
  echo "=== INGRESSES ==="
  kubectl get ingress -n $NAMESPACE -o custom-columns='NAME:.metadata.name,CLASS:.spec.ingressClassName,HOSTS:.spec.rules[*].host'
  echo ""
  echo "=== DEPLOYMENTS ==="
  kubectl get deploy -n $NAMESPACE -o custom-columns='NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image,REPLICAS:.spec.replicas'
  echo ""
  echo "=== STATEFULSETS ==="
  kubectl get sts -n $NAMESPACE -o custom-columns='NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image,REPLICAS:.spec.replicas'
} > cluster-info.txt

cat cluster-info.txt
```

---

## Storage Classes

```bash
# List all storage classes
kubectl get storageclass

# Get default storage class
kubectl get storageclass -o jsonpath='{.items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")].metadata.name}'

# Detailed view
kubectl get storageclass -o wide
```

**What to look for:** The storage class name to use in `persistence.storageClass`

---

## Image Pull Secrets

```bash
# List secrets that look like registry credentials
kubectl get secrets -n posaidon -o custom-columns='NAME:.metadata.name,TYPE:.type' | grep -E 'docker|registry'

# List all secrets (names only)
kubectl get secrets -n posaidon -o name

# Get secret details (without exposing data)
kubectl get secret <secret-name> -n posaidon -o yaml | grep -E '^  name:|^type:'
```

**What to look for:** Secret names like `harbor-pull-secret`, `registry-credentials`, etc. for `imagePullSecrets`

---

## Ingress Configuration

```bash
# List ingress classes available
kubectl get ingressclass

# List ingresses in namespace
kubectl get ingress -n posaidon

# Get ingress with annotations (useful for copying patterns)
kubectl get ingress -n posaidon -o yaml | grep -A 20 'annotations:'

# Get specific ingress details
kubectl get ingress <ingress-name> -n posaidon -o yaml
```

**What to look for:**
- `ingressClassName` (nginx, traefik, etc.)
- Annotations (cert-manager, auth, etc.)
- TLS secret names
- Host patterns

---

## Existing Deployments (Reference)

```bash
# List deployments with images
kubectl get deploy -n posaidon -o custom-columns='NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image'

# Get full deployment spec (good for copying patterns)
kubectl get deploy <deployment-name> -n posaidon -o yaml

# Extract just the container spec
kubectl get deploy <deployment-name> -n posaidon -o jsonpath='{.spec.template.spec.containers[0]}' | jq .

# Get environment variables from a deployment
kubectl get deploy <deployment-name> -n posaidon -o jsonpath='{.spec.template.spec.containers[0].env[*].name}' | tr ' ' '\n'

# Get resource limits/requests
kubectl get deploy <deployment-name> -n posaidon -o jsonpath='{.spec.template.spec.containers[0].resources}' | jq .
```

---

## ConfigMaps and Secrets (Structure Only)

```bash
# List configmaps
kubectl get configmap -n posaidon

# Get configmap keys (not values)
kubectl get configmap <configmap-name> -n posaidon -o jsonpath='{.data}' | jq 'keys'

# Get secret keys (not values)
kubectl get secret <secret-name> -n posaidon -o jsonpath='{.data}' | jq 'keys'

# Export configmap structure
kubectl get configmap <configmap-name> -n posaidon -o yaml | grep -E '^  [a-zA-Z]' | head -20
```

---

## Persistent Volume Claims

```bash
# List PVCs with storage class
kubectl get pvc -n posaidon -o custom-columns='NAME:.metadata.name,STORAGE_CLASS:.spec.storageClassName,SIZE:.spec.resources.requests.storage,STATUS:.status.phase'

# Get PVC details
kubectl get pvc <pvc-name> -n posaidon -o yaml
```

**What to look for:** Storage class name, size patterns used in your environment

---

## Services

```bash
# List services
kubectl get svc -n posaidon

# Get service details
kubectl get svc <service-name> -n posaidon -o yaml
```

---

## Helm Releases

```bash
# List helm releases in namespace
helm list -n posaidon

# Get values from existing release (useful for migration)
helm get values <release-name> -n posaidon

# Get all values (including defaults)
helm get values <release-name> -n posaidon -a

# Get release manifest
helm get manifest <release-name> -n posaidon
```

---

## Node/Cluster Info

```bash
# Get cluster version
kubectl version --short

# Get node info (for resource planning)
kubectl get nodes -o custom-columns='NAME:.metadata.name,VERSION:.status.nodeInfo.kubeletVersion,OS:.status.nodeInfo.osImage'

# Check available resources
kubectl top nodes 2>/dev/null || echo "Metrics server not available"
```

---

## Keycloak Configuration (External Service)

Keycloak runs as an external service outside the cluster. Gather this info from your Keycloak admin console and OIDC discovery endpoint.

### OIDC Discovery Endpoint

```bash
# Get OIDC discovery document (replace with your Keycloak URL)
KEYCLOAK_URL="https://sso.example.com/realms/myrealm"
curl -s "${KEYCLOAK_URL}/.well-known/openid-configuration" | jq .

# Extract specific values
curl -s "${KEYCLOAK_URL}/.well-known/openid-configuration" | jq '{
  issuer: .issuer,
  authorization_endpoint: .authorization_endpoint,
  token_endpoint: .token_endpoint,
  end_session_endpoint: .end_session_endpoint
}'
```

### Values to Collect from Keycloak Admin Console

1. **Realm Settings** → General
   - Realm name (part of the URL)

2. **Clients** → Your client → Settings
   - Client ID → `KEYCLOAK_CLIENT_ID`
   - Valid redirect URIs (should include `https://your-app.com/auth/callback`)
   - Web origins (should include `https://your-app.com`)

3. **Clients** → Your client → Credentials
   - Client secret → `KEYCLOAK_CLIENT_SECRET`

### Required Helm Values from Keycloak

```yaml
proxy:
  env:
    # Use the issuer URL from OIDC discovery (internal access from cluster)
    KEYCLOAK_ISSUER_URL: "https://sso.example.com/realms/myrealm"

    # Client ID from Keycloak admin console
    KEYCLOAK_CLIENT_ID: "anythingllm"

    # Your app's callback URL (must match Keycloak valid redirect URIs)
    KEYCLOAK_REDIRECT_URL: "https://your-app.example.com/auth/callback"

    # External URL users' browsers will use (usually same as ISSUER_URL for external Keycloak)
    KEYCLOAK_EXTERNAL_URL: "https://sso.example.com/realms/myrealm"

  secretEnv:
    # Client secret from Keycloak credentials tab
    KEYCLOAK_CLIENT_SECRET: "your-client-secret"
```

### Test Cluster Connectivity to External Keycloak

```bash
# From your workstation
curl -I https://sso.example.com/realms/myrealm/.well-known/openid-configuration

# From inside the cluster (to verify network policies/firewalls allow access)
kubectl run -it --rm curl-test --image=curlimages/curl -n posaidon -- \
  curl -sI https://sso.example.com/realms/myrealm/.well-known/openid-configuration

# Check DNS resolution from cluster
kubectl run -it --rm dns-test --image=busybox -n posaidon -- \
  nslookup sso.example.com
```

### Common External Keycloak Issues

| Issue | Check |
|-------|-------|
| Connection timeout | Firewall/network policy blocking egress |
| Certificate errors | Cluster needs CA certificate or `--insecure` for testing |
| DNS resolution fails | Check cluster DNS, may need external DNS or hosts entry |
| Redirect mismatch | `KEYCLOAK_REDIRECT_URL` must exactly match Keycloak's valid redirect URIs |

---

## Export for LLM

Create a file to give to the LLM:

```bash
NAMESPACE=posaidon

# Set your external Keycloak URL (gather from your SSO team or admin console)
KEYCLOAK_URL="https://sso.example.com/realms/myrealm"

cat << EOF > environment-config.txt
# Environment Configuration Export
# Feed this to an LLM with helm/prompt.md to configure charts

## Cluster Info
EOF

{
  echo "Kubernetes Version: $(kubectl version --short 2>/dev/null | grep Server || echo 'unknown')"
  echo "Namespace: $NAMESPACE"
  echo ""
  echo "## Storage Classes"
  kubectl get storageclass -o custom-columns='NAME:.metadata.name,PROVISIONER:.provisioner,DEFAULT:.metadata.annotations.storageclass\.kubernetes\.io/is-default-class' 2>/dev/null
  echo ""
  echo "## Ingress Classes"
  kubectl get ingressclass -o custom-columns='NAME:.metadata.name,CONTROLLER:.spec.controller' 2>/dev/null || echo "None found"
  echo ""
  echo "## Image Pull Secrets"
  kubectl get secrets -n $NAMESPACE -o custom-columns='NAME:.metadata.name,TYPE:.type' 2>/dev/null | grep -E 'docker|registry' || echo "None found"
  echo ""
  echo "## Existing Ingress Annotations (for reference)"
  kubectl get ingress -n $NAMESPACE -o jsonpath='{range .items[*]}{.metadata.name}: {.metadata.annotations}{"\n"}{end}' 2>/dev/null || echo "None found"
  echo ""
  echo "## Existing Images in Namespace"
  kubectl get deploy,sts -n $NAMESPACE -o jsonpath='{range .items[*]}{.kind}/{.metadata.name}: {.spec.template.spec.containers[0].image}{"\n"}{end}' 2>/dev/null
  echo ""
  echo "## PVC Storage Classes in Use"
  kubectl get pvc -n $NAMESPACE -o custom-columns='NAME:.metadata.name,STORAGECLASS:.spec.storageClassName,SIZE:.spec.resources.requests.storage' 2>/dev/null || echo "None found"
  echo ""
  echo "## Keycloak (External Service)"
  echo "KEYCLOAK_URL: $KEYCLOAK_URL"
  echo "OIDC Discovery:"
  curl -s "${KEYCLOAK_URL}/.well-known/openid-configuration" 2>/dev/null | jq '{issuer, authorization_endpoint, token_endpoint}' || echo "  (fetch manually or check connectivity)"
  echo ""
  echo "## Manual Input Required"
  echo "- KEYCLOAK_CLIENT_ID: (from Keycloak admin console)"
  echo "- KEYCLOAK_CLIENT_SECRET: (from Keycloak admin console -> Clients -> Credentials)"
  echo "- App Domain: (e.g., anythingllm.example.com)"
} >> environment-config.txt

cat environment-config.txt
```

---

## Troubleshooting Commands

```bash
# Pod status
kubectl get pods -n posaidon -o wide

# Pod logs
kubectl logs -n posaidon deploy/<deployment-name>
kubectl logs -n posaidon deploy/<deployment-name> -c <init-container-name>

# Describe pod (events, errors)
kubectl describe pod -n posaidon -l app.kubernetes.io/name=<app-name>

# Get events
kubectl get events -n posaidon --sort-by='.lastTimestamp' | tail -20

# Check PVC binding
kubectl get pvc -n posaidon

# Test service connectivity from inside cluster
kubectl run -it --rm debug --image=busybox -n posaidon -- sh
# Then: nc -zv <service-name> <port>
```

---

## Common Patterns by Environment

### Harbor Registry
```bash
# Image format
harbor.example.com/project/image:tag

# Pull secret type
kubernetes.io/dockerconfigjson
```

### Rancher-managed Clusters
```bash
# Common storage classes
kubectl get storageclass | grep -E 'longhorn|local-path|nfs'

# Rancher ingress
kubectl get ingressclass | grep -E 'nginx|traefik'
```

### Cert-Manager TLS
```bash
# List cluster issuers
kubectl get clusterissuer

# List issuers in namespace
kubectl get issuer -n posaidon

# Common annotation
# cert-manager.io/cluster-issuer: letsencrypt-prod
```

---

## Sample Output for LLM

Here's an example of what to paste into your LLM along with `helm/prompt.md`:

```
## My Environment

### Kubernetes (from kubectl commands above)
Storage Class: longhorn
Ingress Class: nginx
Image Pull Secret: harbor-pull-secret
Registry: harbor.mycompany.com
Project: ai-tools

Existing Annotations from similar ingress:
  cert-manager.io/cluster-issuer: letsencrypt-prod
  nginx.ingress.kubernetes.io/proxy-body-size: "100m"

App Domain: anythingllm.mycompany.com

### Keycloak (from admin console - external service)
Keycloak Base URL: https://sso.mycompany.com
Realm: employees
Full Realm URL: https://sso.mycompany.com/realms/employees
Client ID: anythingllm-client
Client Secret: abc123-secret-from-credentials-tab
Valid Redirect URIs configured: https://anythingllm.mycompany.com/auth/callback
```

Then the LLM can generate a complete `values-override.yaml` for your environment.

---

## Keycloak Admin Checklist

If you're a **realm admin**, here's exactly what to gather from the admin console:

### From Keycloak Admin Console

1. **Realm Settings** (left sidebar)
   - Note the realm name from the URL or dropdown

2. **Clients** → Click your client (or create one)
   - **Settings tab:**
     - Client ID → `KEYCLOAK_CLIENT_ID`
     - Root URL: `https://your-app-domain.com`
     - Valid redirect URIs: `https://your-app-domain.com/auth/callback`
     - Valid post logout redirect URIs: `https://your-app-domain.com/*`
     - Web origins: `https://your-app-domain.com`
   - **Credentials tab:**
     - Client secret → `KEYCLOAK_CLIENT_SECRET`
   - **Advanced tab** (optional):
     - Check PKCE settings if needed

3. **Construct your URLs:**
   ```
   KEYCLOAK_ISSUER_URL = https://<keycloak-host>/realms/<realm-name>
   KEYCLOAK_EXTERNAL_URL = https://<keycloak-host>/realms/<realm-name>
   KEYCLOAK_REDIRECT_URL = https://<your-app>/auth/callback
   ```

### Quick Copy Template

Fill this out and give to your LLM:

```
## Keycloak Config (I'm realm admin)

Keycloak Host: _______________
Realm Name: _______________
Client ID: _______________
Client Secret: _______________

App will be at: https://_______________
Callback URL: https://_______________/auth/callback
```

### Creating a New Client (if needed)

1. **Clients** → **Create client**
2. **General Settings:**
   - Client type: `OpenID Connect`
   - Client ID: `anythingllm` (or your preferred name)
3. **Capability config:**
   - Client authentication: `ON`
   - Authorization: `OFF`
   - Authentication flow: Check `Standard flow` only
4. **Login settings:**
   - Root URL: `https://your-app.example.com`
   - Valid redirect URIs: `https://your-app.example.com/auth/callback`
   - Valid post logout redirect URIs: `https://your-app.example.com/*`
   - Web origins: `https://your-app.example.com`
5. **Save** → Go to **Credentials** tab → Copy **Client secret**
