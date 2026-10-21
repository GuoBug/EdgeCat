# EdgeCat - Local-First AI Inference Governance Gateway
# Copyright (c) 2026 Guo Qiang. Distributed under Apache-2.0.

.PHONY: all build test clean run

BINARY_NAME=bin/edgecat

all: test build

build:
	@echo "Building EdgeCat with CGO_ENABLED=0..."
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY_NAME) ./cmd/edgecat

test:
	@echo "Running all unit tests..."
	go test -v ./...

run:
	@echo "Starting EdgeCat with example config..."
	go run ./cmd/edgecat -config configs/edgecat.example.yaml

clean:
	@echo "Cleaning up build artifacts..."
	rm -rf bin/ data/*.db data/*.db-wal data/*.db-shm
