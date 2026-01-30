# Helm Chart Values Configuration Prompt

You are configuring the AnythingLLM Stack Helm chart for deployment. Extract environment-specific values from the provided example YAML and generate a values override file.

## Your Task

1. Extract environment-specific configuration from the example YAML I provide
2. Generate a `values.yaml` override file for the AnythingLLM Stack helm chart
3. **DO NOT** modify application behavior settings - only infrastructure/environment settings

## Values You SHOULD Extract and Set

### Images
```yaml
proxy:
  image:
    registry: ""      # e.g., harbor.example.com, gcr.io/project
    repository: ""    # e.g., platform/keycloak-proxy-go
    tag: ""           # e.g., v1.0.0, latest
  imagePullSecrets: [] # e.g., ["harbor-pull-secret"]

anythingllm:
  image:
    registry: ""
    repository: ""
    tag: ""
  imagePullSecrets: []

weaviate:
  weaviate:
    image:
      registry: ""    # leave empty for default (cr.weaviate.io)
      tag: ""         # e.g., 1.34.0
```

### Storage
```yaml
anythingllm:
  persistence:
    storageClass: ""  # e.g., "fast-ssd", "standard", "longhorn"
    size: ""          # e.g., "10Gi", "50Gi"

weaviate:
  weaviate:
    persistence:
      storageClass: ""
      size: ""
```

### Ingress
```yaml
proxy:
  ingress:
    enabled: true/false
    className: ""     # e.g., "nginx", "traefik", "istio"
    annotations: {}   # e.g., cert-manager, auth annotations
    hosts:
      - host: ""      # e.g., "app.example.com"
        paths:
          - path: /
            pathType: Prefix
    tls: []           # TLS configuration if needed
```

### Resources (if specified in example)
```yaml
proxy:
  resources:
    requests:
      cpu: ""
      memory: ""
    limits:
      cpu: ""
      memory: ""
# Same structure for anythingllm and weaviate.weaviate
```

### Pod Settings (if specified)
```yaml
proxy:
  nodeSelector: {}
  tolerations: []
  affinity: {}
  podAnnotations: {}
  podLabels: {}
# Same for anythingllm
```

### Secrets Reference (if using external secrets)
```yaml
proxy:
  existingSecret: ""  # e.g., "proxy-secrets" - use instead of secretEnv

anythingllm:
  existingSecret: ""
```

## Values You Must NOT Change

These settings control application behavior. Changing them will break the app:

```yaml
# DO NOT MODIFY THESE - Application Configuration
proxy:
  env:
    PORT: "8080"
    ANYLLM_URL: "http://anythingllm:3001"  # Internal service URL
    # All other env vars control app behavior
  secretEnv:
    # Only set values, don't remove keys
    ANYLLM_API_KEY: ""
    KEYCLOAK_CLIENT_SECRET: ""
    SESSION_SECRET: ""

anythingllm:
  env:
    STORAGE_DIR: "/app/server/storage"
    SIMPLE_SSO_ENABLED: "true"
    SIMPLE_SSO_NO_LOGIN: "true"
    VECTOR_DB: "weaviate"
    WEAVIATE_ENDPOINT: "http://weaviate:80"  # Internal service URL
    # JWT_SECRET can be changed but must remain set
  secretEnv:
    WEAVIATE_API_KEY: ""  # Only set value, don't remove

weaviate:
  weaviate:
    service:
      type: ClusterIP
      port: 8080
    grpcService:
      enabled: false
    initContainers:
      sysctlInitContainer:
        enabled: false
```

## Output Format

Generate ONLY the values that need to be overridden. Use this structure:

```yaml
# Environment: [extracted from example]
# Generated for: AnythingLLM Stack Helm Chart

proxy:
  # ... only include values being overridden

anythingllm:
  # ... only include values being overridden

weaviate:
  # ... only include values being overridden
```

## Special Cases

### Keycloak URLs
If the example contains Keycloak configuration, update these proxy env vars:
```yaml
proxy:
  env:
    KEYCLOAK_ISSUER_URL: ""      # Internal Keycloak URL
    KEYCLOAK_CLIENT_ID: ""
    KEYCLOAK_REDIRECT_URL: ""    # Must match ingress host
    KEYCLOAK_EXTERNAL_URL: ""    # Browser-accessible Keycloak URL
```

### SSO Redirect
If ingress host changes, update:
```yaml
anythingllm:
  env:
    SIMPLE_SSO_NO_LOGIN_REDIRECT: ""  # https://<ingress-host>/login
```

### Session Security (HTTPS)
If TLS is enabled:
```yaml
proxy:
  env:
    SESSION_SECURE: "true"
    SESSION_SAMESITE: "none"  # or "lax" for same-domain
```

## Example Input

I will provide a YAML file like:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    some.annotation/key: value
spec:
  template:
    spec:
      imagePullSecrets:
        - name: my-registry-secret
      containers:
        - image: harbor.corp.com/platform/my-app:v2.1.0
          resources:
            requests:
              memory: "256Mi"
---
apiVersion: v1
kind: PersistentVolumeClaim
spec:
  storageClassName: fast-nvme
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - app.example.com
      secretName: app-tls
  rules:
    - host: app.example.com
```

From this, extract: registry, tag, pull secrets, storage class, ingress class, annotations, host, TLS config.

---

## Now Process My Example

Here is my environment's example YAML:

```yaml
[PASTE YOUR EXAMPLE YAML HERE]
```

Generate the values override file.
