# Airgapped Installation Guide

This guide covers installing the proxy + AnythingLLM + Weaviate in a network-restricted environment.
The main goals are:
- Mirror images into an internal registry.
- Vendor Helm dependencies so installs do not need internet access.
- Provide config via ConfigMaps/Secrets instead of inline env.

## 1) Prepare images in a connected environment

You need to mirror all images used by the charts into your internal registry.
At minimum:
- Proxy: `harbor.localhost/mapache/keycloak-proxy-go:<tag>`
- AnythingLLM: `harbor.localhost/mapache/anythingllm:<tag>`
- Weaviate: `semitechnologies/weaviate:<tag>` (set in `helm/weaviate/values.yaml`)

Example workflow (replace registry/paths as needed):
```powershell
# Pull from public registry
docker pull semitechnologies/weaviate:1.34.0

# Tag for your internal registry
docker tag semitechnologies/weaviate:1.34.0 <REGISTRY>/<PROJECT>/weaviate:1.34.0

# Push into the airgapped registry
docker push <REGISTRY>/<PROJECT>/weaviate:1.34.0
```

Repeat for AnythingLLM and the proxy image.

## 2) Vendor Helm dependencies (online)

Weaviate is a Helm dependency. Vendor it once in a connected environment:
```powershell
helm repo add weaviate https://weaviate.github.io/weaviate-helm
helm repo update
helm dependency update helm/weaviate
```

This creates `helm/weaviate/charts/` and `helm/weaviate/Chart.lock`.
Commit/copy those into the airgapped environment so `helm` does not need to fetch anything.

## 3) Create an airgapped values override

Create a file like `airgap.values.yaml` with your internal registry and endpoints:
```yaml
anythingllm:
  image:
    registry: "<REGISTRY>"
    repository: "<PROJECT>/anythingllm"
    tag: "<TAG>"
  env:
    WEAVIATE_ENDPOINT: "http://weaviate:80"
  existingSecret: "anythingllm"

proxy:
  image:
    registry: "<REGISTRY>"
    repository: "<PROJECT>/keycloak-proxy-go"
    tag: "<TAG>"
  existingSecret: "anythingllm-proxy"
  ingress:
    nameOverride: "proxy"

weaviate:
  image:
    tag: "1.34.0"
  persistence:
    storageClass: "<STORAGE_CLASS>"
```

## 4) Create Secrets (airgapped cluster)

Create required secrets once per namespace.

Proxy secret (required keys):
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: anythingllm-proxy
type: Opaque
stringData:
  ANYLLM_API_KEY: "<ANYLLM_ADMIN_API_KEY>"
  KEYCLOAK_CLIENT_SECRET: "<KEYCLOAK_CLIENT_SECRET>"
  SESSION_SECRET: "<RANDOM_32B64>"
```

AnythingLLM secret (optional, for Weaviate API key):
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: anythingllm
type: Opaque
stringData:
  WEAVIATE_API_KEY: "<WEAVIATE_API_KEY>"
```

## 5) Install in the airgapped cluster

```powershell
helm upgrade --install weaviate helm/weaviate -n <NAMESPACE> -f helm/weaviate/values.yaml
helm upgrade --install anythingllm helm/anythingllm -n <NAMESPACE> -f helm/anythingllm/values.yaml
helm upgrade --install proxy helm/proxy -n <NAMESPACE> -f helm/proxy/values.yaml
```

Note: Use an existing namespace if you do not have permission to create new ones.

Then apply your overrides:
```powershell
helm upgrade --install weaviate helm/weaviate -n <NAMESPACE> -f helm/weaviate/values.yaml -f airgap.values.yaml
helm upgrade --install anythingllm helm/anythingllm -n <NAMESPACE> -f helm/anythingllm/values.yaml -f airgap.values.yaml
helm upgrade --install proxy helm/proxy -n <NAMESPACE> -f helm/proxy/values.yaml -f airgap.values.yaml
```

## Notes for strict environments

- Pod security defaults are already set (non-root, seccomp RuntimeDefault, no SA token).
- If your cluster enforces `readOnlyRootFilesystem=true` for AnythingLLM, set:
  - `containerSecurityContext.readOnlyRootFilesystem: true`
  - an `extraVolume` + `extraVolumeMount` for `/tmp`.
- Weaviate persistence requires a storage class; set `persistence.storageClass`.
