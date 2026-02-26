.PHONY: build test fmt lint release-build

VERSION ?= v1.0.0
COMMIT ?= $(shell git rev-parse --short HEAD)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/safe-agentic-world/janus/internal/version.Version=$(VERSION) -X github.com/safe-agentic-world/janus/internal/version.Commit=$(COMMIT) -X github.com/safe-agentic-world/janus/internal/version.BuildDate=$(BUILD_DATE)

build:
	go build ./cmd/janus

test:
	go test ./...

fmt:
	gofmt -w .

lint:
	go vet ./...

release-build:
	go build -ldflags "$(LDFLAGS)" -o bin/janus ./cmd/janus
