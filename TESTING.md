# Testing

Run from the repository root. Go 1.25+ and Python 3.10+ are required;
Node 24 is used for the TypeScript source tests.

The repository selects Go 1.26.8 via `go.mod`, matching CI. Keep automatic
toolchain selection enabled or install that version explicitly. Go 1.25
is the language baseline, not a recommendation to build with an unpatched
standard library. Verify newer patches against the
[official Go releases](https://go.dev/dl/).

## Go

```bash
go build ./cmd/nomos
go test ./...
go vet ./...
go test -race ./...
```

Race tests need a supported C compiler/CGO toolchain. Use focused tests
while editing, for example `go test ./internal/gateway ./internal/service`.
Format changed Go files with `gofmt`. There is no fixed coverage percentage;
add assertions for allowed, denied, approval, and failure paths you change.

## Permission Regression Suite

```bash
go run ./cmd/nomos test --suite examples/local-inbox/permissions.json --bundle examples/local-inbox/policy.yaml
```

This checks policy only, with no gateway or tool execution. Exit codes:
0 all expectations match, 1 regression, 2 invalid suite/configuration.

## Python And Real LangGraph Integration

Create a virtual environment as shown in the [quickstart](docs/quickstart.md),
then use its Python executable for:

```bash
python -m pip install -e "./sdk/python[langgraph]" build
python -m unittest discover -s sdk/python -p "test_*.py" -v
python -m unittest discover -s examples/local-inbox -p "test_*.py" -v
python examples/local-inbox/demo.py --auto-approve
python examples/local-inbox/demo.py --reject
python -m build ./sdk/python --outdir .tmp/python-dist
python scripts/check_docs.py
```

Integration tests start a real Go gateway and use real LangGraph. They
exercise delivery, review/resume, denial, expired/rejected approval,
changed arguments, unauthorized reviewers, and local-provider deduplication.
No model, email service, or account is used. Set `NOMOS_TEST_BINARY`
to test a binary outside the repository root.

Inspect a built wheel by installing it into a fresh virtual environment and
importing `nomos_sdk` and `nomos_langgraph` from outside the checkout.
Temporary demo directories retain credentials; remove only the specific
directories printed by your runs when finished.

## TypeScript And MCP Compatibility

```bash
node --experimental-strip-types --test sdk/typescript/test_nomos_sdk.ts
go test ./internal/mcp
```

The opt-in reference contract is
`NOMOS_MCP_CONTRACT_TESTS=1 go test ./internal/mcp -run "TestReferenceMCPContract|TestReferenceContractManifest" -count=1 -v`
(PowerShell: set the environment variable separately).
Check the reference manifest before installing any optional dependencies.

CI also runs workflow linting, normalization across operating systems,
bypass tests, dependency/vulnerability checks, and release dry runs.
Use `actionlint` after changing GitHub workflows.
