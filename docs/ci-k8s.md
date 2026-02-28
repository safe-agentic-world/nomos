# CI And K8s Readiness

## CI

GitHub Actions workflow: `.github/workflows/ci.yml`

Checks:
- `go test ./...`
- container image build (`docker build`)

## Kubernetes

Reference manifests in `deploy/k8s/`:
- `configmap.yaml`
- `deployment.yaml`
- `service.yaml`

Apply:

```powershell
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
```

Design notes:
- stateless mode enabled in sample config
- readiness/liveness probes on `/healthz`
- resource requests/limits set
- multiple replicas for horizontal scaling
- graceful termination via deployment `terminationGracePeriodSeconds`
