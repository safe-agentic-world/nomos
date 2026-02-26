.PHONY: build test fmt lint

build:
	go build ./cmd/janus

test:
	go test ./...

fmt:
	gofmt -w .

lint:
	go vet ./...
