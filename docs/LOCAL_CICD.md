# Local CI/CD (GitLab + Harbor + Rancher + Argo CD)

## CI variables (GitLab)

Preferred (robot credentials):
- HARBOR_ROBOT=robot$rob
- HARBOR_ROBOT_TOKEN=<robot token>

Fallback (admin credentials):
- HARBOR_USERNAME=admin
- HARBOR_PASSWORD=<password from .env>

Existing (if used):
- ARGOCD_SERVER
- ARGOCD_USERNAME
- ARGOCD_PASSWORD
- SONAR_HOST_URL
- SONAR_TOKEN

## Docker Desktop: Harbor insecure registry

If your runner or Docker-in-Docker cannot reach harbor.localhost over HTTPS, add to Docker Desktop
Settings -> Docker Engine and restart:

{
  "insecure-registries": ["harbor.localhost"]
}

## Notes

- Robot accounts are for CLI/CI only; they cannot log into the Harbor UI.
- If DinD cannot resolve harbor.localhost, add a hosts entry or use an alternate registry host.

## Helm charts to Harbor (OCI)

CI publishes charts to:
- oci://harbor.localhost/mapache

Charts are packaged with version:
- 1.0.0
