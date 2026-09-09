# Developer Workflow Validation

Local validation on September 8, 2026. This is a working-tree verification
record, not a published release or hosted CI result.

## Passed Locally

- Go 1.26.8 on Windows amd64: CLI build, `go test -count=1 ./...`, and
  `go vet ./...`.
- `govulncheck ./...`: no vulnerabilities found with the pinned toolchain.
  The machine's original Go 1.26.0 build reported 17 reachable standard-library
  vulnerabilities; the repository and workflows now select Go 1.26.8.
- All six offline inbox permission cases, in text and JSON formats. The
  Linux amd64 cross-built binary also passed the suite under WSL Ubuntu.
- Python 3.12.4: 16 SDK unit tests and seven real-gateway integration tests,
  using LangGraph 1.2.11. Allow/deny/review, forged resume, unauthorized
  reviewers, expiry, rejection, changed arguments, and deduplication passed.
- Scripted approved and rejected demos: only approval delivered a local
  SQLite message. No model or email provider was used.
- TypeScript source tests on Node 24.13.1.
- Opt-in MCP reference-contract suite, including stdio and streamable HTTP
  fixture scenarios. This is the repository's contract harness, not a live
  third-party-service certification.
- Quickstart doctor returned READY with BEST_EFFORT assurance.
- Python wheel and source distribution built; the wheel imported from a
  clean temporary environment outside the checkout. Apache-2.0 license
  metadata and the included license file were checked.
- `actionlint`, local Markdown link checks, and `git diff --check`.
  Go formatting matched after normalizing Windows checkout line endings.

## Limits And Follow-Up

- Race execution could not run locally: CGO is disabled by default and an
  explicit CGO attempt found no `gcc`. Neither the Windows environment nor
  WSL had a C compiler available. The existing Linux CI race job is retained.
- Full Python integration was validated on Windows. The additional WSL
  environment lacked `ensurepip`/`python3-venv`; its CLI permission smoke
  passed, but a Linux Python integration run was not completed locally.
- CI now includes Windows/Linux and Python 3.10/3.12 integration jobs.
  Hosted matrix, CodeQL, dependency-review, and release jobs were not
  triggered from this workspace. No release or package was published.
- The demo uses in-memory graph checkpoints and caller-attested reports.
  External provider delivery, durable graph restart, and exactly-once
  execution are not claimed.

## Workspace Changes

Removed the standalone coding-agent job runner, its workflow/examples,
misleading callback examples, broad deployment guides, and two generated
Python bytecode files. These tracked removals are recoverable from Git.
No Kubernetes manifests or Helm charts were present. Existing `AGENTS.md`
and ignored developer planning files were preserved.

Demo databases and credentials remain in the specific temporary directories
printed by runs. Treat them as local development data; do not publish them.
Reproduce checks using [TESTING.md](../TESTING.md).
