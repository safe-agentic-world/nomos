# CI And K8s Readiness

## CI

Primary workflows:

- `.github/workflows/ci.yml` (`Enterprise CI`)
- `.github/workflows/codeql.yml` (`CodeQL`)
- `.github/workflows/auto-tag-release.yml` (`Auto Tag Release`)
- `.github/workflows/release.yml` (`Release`)

Checks:
- workflow lint (`actionlint`)
- formatting, `go vet`, and `go build`
- `go test ./...`
- normalization corpus matrix (Linux/macOS/Windows)
- bypass suite
- race tests + `nomos doctor` smoke
- `govulncheck`
- container image build (`docker buildx`)
- release dry-run build on pull requests
- CodeQL analysis on `main` and pull requests

## Kubernetes

Reference manifests in `deploy/k8s/`:
- `configmap.yaml`
- `deployment.yaml`
- `service.yaml`
- `networkpolicy.yaml`
- `serviceaccount.yaml`
- `strong-guarantee.yaml`

Apply:

```powershell
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
```

For the stronger reference posture, use:

```powershell
kubectl apply -f deploy/k8s/strong-guarantee.yaml
```

Design notes:
- stateless mode enabled in sample config
- readiness/liveness probes on `/healthz`
- resource requests/limits set
- multiple replicas for horizontal scaling
- graceful termination via deployment `terminationGracePeriodSeconds`
- the release path is workflow-managed: successful `main` CI can tag, publish a GitHub Release, and update Homebrew/Scoop manifests
