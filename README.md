# EdgeCat: Local-First AI Inference Governance Gateway

<p align="center">
  <b>English</b> •
  <a href="README_zh.md">中文</a>
</p>

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![CGO_ENABLED](https://img.shields.io/badge/CGO_ENABLED-0-success?style=flat)]()
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-Local--First_Dual--Track-orange)]()

> **EdgeCat** is an ultra-lightweight, deterministic, local-first AI inference governance gateway written in Go 1.22+ and compiled with `CGO_ENABLED=0` pure static binaries.  
> Purpose-built to solve real-world engineering bottlenecks when bridging local edge inference engines (Ollama, vLLM, llama.cpp) with cloud fallback tiers (OpenAI, DeepSeek, Qwen).

---

## Core Pain Points & Engineering Solutions

In local-first and hybrid AI architectures, dispatching traffic directly to local GPU workers introduces four severe operational hazards:
1. **Unreliable GPU Hang Detection**: Operating system memory metrics cannot reliably reflect GPU saturation; stalled local inference hangs downstream client connections indefinitely.
2. **PII Placeholder Fragmentation Across SSE Chunks**: When streaming tokens over Server-Sent Events (SSE), deterministic placeholders are frequently split across token chunk boundaries (e.g., `{{EC_PII_` in Chunk 1 and `PHONE_1}}` in Chunk 2), causing naive regex rehydration to fail.
3. **Contract Drift & Code Fence Violations**: Local LLMs often ignore `response_format` and wrap outputs in unwanted ````json markdown code blocks, breaking downstream strict serialization contracts.
4. **Synchronous Audit Latency Penalties**: Traditional gateways write audit logs directly within the HTTP request goroutine, causing severe Time-To-First-Token (TTFT) degradation.

**EdgeCat eliminates these failure modes through five deterministic mechanisms:**

```
                       ┌──────────────────────────────────────────────┐
                       │          Client (OpenAI SDK / HTTP)          │
                       └──────────────────────┬───────────────────────┘
                                              │ POST /v1/chat/completions
                                              ▼
                        ┌────────────────────────────────────────────┐
                        │  PII Filter: Regex Masker & Memory Vault   │
                        │  (Phone / Email / IPv4 / APIKey Masking)   │
                        └─────────────────────┬──────────────────────┘
                                              ▼
                        ┌────────────────────────────────────────────┐
                        │        Tier Router & Model Aliasing        │
                        └───────┬────────────────────────────┬───────┘
          Local Semaphore Free  │                            │ Local Saturated /
           & TTFT < 3500ms      │                            │ TTFT Exceeded / Refused
                                ▼                            ▼
            ┌───────────────────────┐            ┌───────────────────────┐
            │   Local Tier (Ollama) │            │   Cloud Tier (OpenAI) │
            │   e.g. qwen2.5:7b     │            │   e.g. gpt-4o-mini    │
            └───────────┬───────────┘            └───────────┬───────────┘
                        │                                    │
                        └─────────────────┬──────────────────┘
                                          │ Raw Response / SSE Stream
                                          ▼
                      ┌───────────────────────────────────────────────┐
                      │ Sliding-Window SSE Rehydrator & JSON Guard    │
                      │ (Chunk Stitching + Code Fences Stripping)     │
                      └───────────────────┬───────────────────────────┘
                                          │
                                          ├─► Flush to Client (http.Flusher)
                                          │
                                          ▼ (Non-blocking Bounded Chan)
                      ┌───────────────────────────────────────────────┐
                      │    Async SQLite Logger (modernc.org/sqlite)   │
                      │    WAL + NORMAL PRAGMA (Batch Worker)         │
                      └───────────────────────────────────────────────┘
```

---

## Key Architectural Pillars

### 1. Sliding-Window SSE Rehydration
- **Ingress Masking**: Inbound requests are scanned for Chinese/international mobile numbers, email addresses, private IPv4 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8), and API keys. Sensitive entities are substituted with deterministic tokens `{{EC_PII_<TYPE>_<INDEX>}}` and stored in a request-scoped in-memory `Vault`.
- **Egress Rehydration**: Implements a dual-cursor sliding-window streaming buffer. If an unclosed placeholder prefix (such as `{{EC_` or `{{EC_PII_`) is detected at the tail of an incoming chunk, the gateway holds back the unclosed slice in a lightweight pending buffer while flushing safe leading tokens immediately. Once subsequent chunks close the placeholder, the original value is restored and flushed via `http.Flusher`.

### 2. Concurrency Semaphore & TTFT Watchdog Fallback
- Replaces OS memory guesswork with a strict channel semaphore (`chan struct{}`) bounded by `max_concurrent_local`.
- Incorporates a **Time-To-First-Token (TTFT) Circuit Breaker**: when dispatching to the local worker, an independent timer monitors the first byte/chunk. If local concurrency is saturated, connections are refused, or TTFT exceeds `ttft_timeout_ms`, the gateway silently cancels the local context, releases the semaphore, and re-routes the redacted payload to the Cloud Fallback Tier **before any headers are flushed to the client**.

### 3. Transparent Model Aliasing
- Upstream applications use unified logical names (e.g., `default` or `gpt-4o-mini`).
- EdgeCat dynamically rewrites the request model: mapping to the configured local model (`qwen2.5:7b`) on the local tier, or the cloud model on fallback, with automatic recalculation of HTTP `Content-Length`.

### 4. Strict JSON Contract Guard & Bounded Repair Loop
- When `response_format: {"type": "json_object"}` or header `X-EdgeCat-Strict-JSON: true` is present, the gateway automatically strips markdown fences (````json ... ````) and cleans trailing whitespace.
- If syntax validation fails, EdgeCat initiates at most **one bounded repair call** under strict timeout to prompt the model for valid JSON, preventing runaway recursion.

### 5. Lock-Free Asynchronous SQLite Batch Audit
- Powered by `modernc.org/sqlite` (pure Go, zero CGO). Uses `_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)` for high-throughput single-writer performance.
- HTTP handlers push audit entries (`RequestID`, `RouteTarget`, `Model`, `LatencyMs`, `TTFTMs`, `PIIRedactedCount`, `Status`) into a bounded channel (capacity 10,000) using a non-blocking `select-default` pattern. A dedicated background worker flushes batches by threshold (50 items) or ticker interval.

---

## Quickstart

### 1. Build
EdgeCat supports 100% CGO-free static compilation:
```bash
# Using Makefile
make build

# Or direct Go build:
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/edgecat ./cmd/edgecat
```

### 2. Run Test Suite
```bash
make test
# Or execute:
go test -v ./...
```

### 3. Configuration & Startup
Review `configs/edgecat.example.yaml`:
```yaml
server:
  host: "0.0.0.0"
  port: 8080

local:
  endpoint: "http://127.0.0.1:11434/v1"
  max_concurrent_local: 2
  ttft_timeout_ms: 3500
  model_mapping:
    "default": "qwen2.5:7b"
    "gpt-4o-mini": "qwen2.5:7b"

cloud:
  endpoint: "https://api.openai.com/v1"
  api_key: "sk-your-cloud-api-key"
  timeout_ms: 60000
  model_mapping:
    "default": "gpt-4o-mini"
    "qwen2.5:7b": "gpt-4o-mini"

filter:
  enabled: true
  mask_phone: true
  mask_email: true
  mask_ipv4: true
  mask_apikey: true

contract:
  strict_json_enabled: true
  max_repair_attempts: 1

audit:
  sqlite_path: "data/edgecat_audit.db"
  batch_size: 50
  flush_interval_ms: 1000
```

Start the gateway:
```bash
./bin/edgecat -config configs/edgecat.example.yaml
```

---

## Endpoints

EdgeCat provides full OpenAI API wire compatibility:
- **`POST /v1/chat/completions`**: Supports both standard JSON payloads and real-time SSE streaming (`stream: true`).
- **`GET /health`**: Returns real-time health metrics, active concurrency slots, fallback statistics, and audit pipeline throughput.
- **`GET /v1/models`**: OpenAI-compatible model catalog discovery.

---

## Human-AI Collaboration & Design Philosophy

This project was built by **Guo Qiang** through an active **AI Pair Programming** and **"Learning by Doing"** workflow:
- **Human-driven inputs**: Rooted in real production pain points—GPU cold-start hangs, local out-of-memory cascading failures, and sensitive data leakage over streaming LLM connections.
- **AI-driven inputs**: Focused on foundational systems constraints—sliding-window streaming state machines, cross-packet SSE placeholder stitch buffers, silent pre-header HTTP fallback, and lock-free single-worker WAL batching.

Constructive reviews and architectural discussions on deterministic AI workflows, DAG engines, and edge systems are warmly welcomed!

---

> **About the Author**  
> **Guo Qiang (GuoBug)**, Product Engineer specializing in platform engineering and growth. Currently focused on AI workflow orchestration, DAG state machines, and deterministic system architectures.  
> Open Source & Homepage: [https://github.com/GuoBug](https://github.com/GuoBug) · [https://guobug.github.io](https://guobug.github.io)  
> Inquiries and discussions on workflow engine architecture, topological scheduling, and developer experience are warmly welcomed.
