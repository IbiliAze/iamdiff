BINARY := iamdiff
PKG    := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build test lint fmt vet cover clean deps demo

all: fmt vet test build

build:
	go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/iamdiff

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

# Phase 2: swap the stdlib flag dispatch for Cobra and add the AWS SDK.
deps:
	go get github.com/spf13/cobra@latest
	go get github.com/spf13/viper@latest
	go get github.com/aws/aws-sdk-go-v2/config@latest
	go get github.com/aws/aws-sdk-go-v2/service/iam@latest
	go get github.com/aws/aws-sdk-go-v2/service/organizations@latest
	go mod tidy

demo: build
	./bin/$(BINARY) policy examples/before.json examples/after.json || true

clean:
	rm -rf bin coverage.out
