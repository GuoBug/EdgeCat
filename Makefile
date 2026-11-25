# EdgeCat - Local-First AI Inference Governance Gateway
# Copyright (c) 2026 Guo Qiang. Distributed under Apache-2.0.

.PHONY: all build test check clean run

BINARY_NAME ?= bin/edgecat
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE  ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
LDFLAGS     := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

all: test build

build:
	@echo "Building EdgeCat ($(VERSION)) with CGO_ENABLED=0..."
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/edgecat

test:
	@echo "Running all unit tests..."
	go test -v ./...

check: build
	@echo "Running offline pre-flight check against example config..."
	./$(BINARY_NAME) check -config configs/edgecat.example.yaml -offline

run:
	@echo "Starting EdgeCat with example config..."
	go run ./cmd/edgecat -config configs/edgecat.example.yaml

clean:
	@echo "Cleaning up build artifacts..."
	rm -rf bin/ dist/ data/*.db data/*.db-wal data/*.db-shm
