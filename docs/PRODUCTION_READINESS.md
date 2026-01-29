# Production Readiness Checklist

Use this to move from dev defaults to production-grade deployments.

## Core
- Set `image.registry`, `image.repository`, and `image.tag` to your internal registry.
- Provide required secrets via `existingSecret`:
  - Proxy: `ANYLLM_API_KEY`, `KEYCLOAK_CLIENT_SECRET`, `SESSION_SECRET`
  - AnythingLLM: `WEAVIATE_API_KEY` (if using Weaviate auth)
- Set `SESSION_SECURE=true` and `SESSION_SAMESITE=none` when using HTTPS + cross-site auth.

## Kubernetes hardening
- Enable `podDisruptionBudget` for each chart.
- Enable `autoscaling` where needed.
- Enable `networkPolicy` and define explicit `ingress`/`egress` rules.
- Validate `podSecurityContext` and `containerSecurityContext` against your cluster policy.
- For strict clusters, keep Weaviate `grpcService.enabled=false` and `service.type=ClusterIP`.
- Disable Weaviate `initContainers.sysctlInitContainer` if privileged init containers are blocked.

## Storage
- Set `persistence.storageClass` for AnythingLLM and Weaviate.
- Ensure PVC size aligns with expected usage.

## Weaviate
- Confirm the Service endpoint and set `WEAVIATE_ENDPOINT` appropriately.
- If using API key auth, set `WEAVIATE_API_KEY` and enable Weaviate auth in its chart.

## Helm dependency
- `helm/weaviate/charts` should be vendorized before airgapped deploys.
- Install into an existing namespace if you do not have permission to create namespaces.

## CI
- Ensure Helm lint + template jobs run for all charts.
- Keep go vet/go test in place for proxy changes.
