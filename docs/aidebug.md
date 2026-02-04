# AI Debug Playbook (Rancher/Kubernetes)

This guide is for AI-assisted debugging of the AnythingLLM + Proxy + Weaviate stack in Rancher/Kubernetes.  
**Human-in-the-loop is mandatory.** The AI must ask before making any changes and must report findings clearly.

## Safety & Process
- **Ask before making changes** (deployments, secrets, Helm upgrades, deletions).
- **Read-only first**: gather evidence before proposing fixes.
- **Never expose secrets**: redact tokens, client secrets, API keys.

## 0) Confirm Context (Ask the Human)
- Cluster name / context
- Namespace
- Release name(s)
- Ingress host(s) and expected URLs
- Any recent changes

## 1) Check Pods & Deployments
```
kubectl get pods -n <ns>
kubectl get deploy -n <ns>
kubectl get sts -n <ns>
```
Look for CrashLoopBackOff, pending pods, or zero replicas.

## 2) Verify Services & Endpoints
```
kubectl get svc -n <ns>
kubectl get endpoints -n <ns>
```
Ensure each service has endpoints (no empty subsets).

## 3) Validate Ingress Routing
```
kubectl get ingress -A | rg -i "<host>"
kubectl describe ingress -n <ns> <ingress-name>
```
Confirm:
- Host matches expected URL
- Paths are present (`spec.rules[0].http.paths`)
- Backend points to **proxy** service

## 4) Check Required Secrets & Configs
```
kubectl get secret -n <ns>
kubectl get configmap -n <ns>
```
Verify keys exist (redact values):
- `ANYLLM_API_KEY`
- `KEYCLOAK_CLIENT_SECRET`
- `SESSION_SECRET`

## 5) Validate Env Vars on Pods
```
kubectl describe pod -n <ns> <pod> | rg -n "Environment|KEYCLOAK|ANYLLM|SESSION"
```
Confirm required envs are set. Missing keys = install/values issue.

## 6) Connectivity Checks
From proxy pod:
```
kubectl exec -n <ns> <proxy-pod> -- curl -sS http://anythingllm:3001/healthz
kubectl exec -n <ns> <proxy-pod> -- curl -sS http://weaviate:80/v1/.well-known/ready
```
Also check Keycloak issuer well-known:
```
kubectl exec -n <ns> <proxy-pod> -- curl -sS https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration
```

## 7) Proxy Debug Endpoint (if enabled)
- Requires `DEBUG_LOGGING=true`
- URL: `https://<proxy-host>/debug`

## 8) Common Failure Patterns
### Login Loop
- `SIMPLE_SSO_NO_LOGIN_REDIRECT` must be **/logged-out**
- Ingress must route the host to **proxy**, not AnythingLLM

### Kyverno Admission Denied
- Missing resource limits
- Disallowed storageClass
- Disallowed image registry

### AnythingLLM 404 on /logged-out
- User is hitting AnythingLLM ingress directly
- Fix: use proxy host; disable AnythingLLM ingress after setup

## 9) Always Report Back
