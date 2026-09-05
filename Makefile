BINARY := iamdiff
PKG    := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build test lint fmt vet cover clean demo catalogue layering

all: fmt vet test build

build:
	go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/$(BINARY) .

test:
	go test -race -count=1 $(PKG)

cover:
	go test -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out | tail -1

fmt:
	gofmt -l -w .

vet:
	go vet $(PKG)

lint:
	golangci-lint run

# Mirrors the CI layering guard: no core package may import a provider.
layering:
	@bash -c 'set -euo pipefail; \
	  mapfile -t core < <(go list ./internal/... | grep -v "/internal/provider"); \
	  deps=$$(go list -deps "$${core[@]}"); \
	  if grep -q "iamdiff/internal/provider" <<<"$$deps"; then echo "layering violated"; exit 1; fi; \
	  echo "layering ok"'

catalogue:
	./scripts/gen-catalogue-aws.sh internal/provider/aws/data/catalogue.json

demo: build
	./bin/$(BINARY) policy examples/before.json examples/after.json || true

clean:
	rm -rf bin coverage.out
