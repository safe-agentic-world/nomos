# Strong-Guarantee Deployment

This is the golden path for a reproducible strong-guarantee Nomos deployment.

## Kubernetes Golden Path

1. Build the image:

```bash
go build -o ./bin/nomos ./cmd/nomos
docker build -t nomos:local .
```

2. Apply the single reference manifest:

```bash
kubectl apply -f deploy/k8s/strong-guarantee.yaml
```

The manifest deploys:

- the Nomos gateway
- a locked-down `sample-agent` pod
- a Nomos-only egress policy for the sample agent
- a restricted Nomos egress policy for approved upstream access

3. Confirm health:

```bash
kubectl get pods -l app=nomos
kubectl get pods -l app=sample-agent
kubectl get networkpolicy nomos-egress
kubectl get networkpolicy sample-agent-egress
```

4. Run doctor against the strong-guarantee config:

```bash
go run ./cmd/nomos doctor -c ./config.example.json --format json
```

## CI Golden Path

Use the reference workflow in `deploy/ci/github-actions-hardened.yml` as the hardened baseline:

- runner job has no direct credential injection into agent steps
- Nomos is the policy gate for governed actions
- doctor runs in strong-guarantee mode before agent tasks begin

## Operational Expectations

- Direct agent egress is blocked by runtime network policy.
- The sample agent can only egress to the Nomos gateway on TCP 8080.
- Enterprise identity is asserted by the platform.
- Agent-visible effects occur only through Nomos-mediated actions.
- Denied bypass attempts are auditable.

## Scope

This provides a reference deployment and readiness checks. It does not yet prove mediation coverage across every environment; that precision is deferred to later assurance-focused work.
