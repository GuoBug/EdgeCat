# EdgeCat: Local-First AI Inference Governance Gateway

<p align="center">
  <b>English</b> •
  <a href="README_zh.md">中文</a>
</p>

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![CGO_ENABLED](https://img.shields.io/badge/CGO_ENABLED-0-success?style=flat)]()
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-Local--First_Dual--Track-orange)]()

> **EdgeCat** is an ultra-lightweight, deterministic, local-first AI inference governance gateway written in Go 1.26+ and compiled with `CGO_ENABLED=0` pure static binaries.  
> Purpose-built to solve real-world engineering bottlenecks when bridging local edge inference engines (Ollama, vLLM, llama.cpp) with cloud fallback tiers (OpenAI, DeepSeek, Qwen).

---

## Core Pain Points & Engineering Solutions

In local-first and hybrid AI architectures, dispatching traffic directly to local GPU workers introduces four severe operational hazards:
1. **Unreliable GPU Hang Detection**: Operating system memory metrics cannot reliably reflect GPU saturation; stalled local inference hangs downstream client connections indefinitely.
2. **PII Placeholder Fragmentation Across SSE Chunks**: When streaming tokens over Server-Sent Events (SSE), deterministic placeholders are frequently split across token chunk boundaries (e.g., `{{EC_PII_` in Chunk 1 and `PHONE_1}}` in Chunk 2), causing naive regex rehydration to fail.
3. **Contract Drift & Code Fence Violations**: Local LLMs often ignore `response_format` and wrap outputs in unwanted ````json markdown code blocks, breaking downstream strict serialization contracts.
4. **Synchronous Audit Latency Penalties**: Traditional gateways write audit logs directly within the HTTP request goroutine, causing severe Time-To-First-Token (TTFT) degradation.

**EdgeCat eliminates these failure modes through six deterministic mechanisms:**

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
- `contract.strict_json_enabled` is the master switch. Once enabled, when `response_format: {"type": "json_object"}` or header `X-EdgeCat-Strict-JSON: true` is present, the gateway strips markdown fences (````json ... ````) and cleans trailing whitespace.
- If syntax validation fails, EdgeCat initiates at most **one bounded repair call** under strict timeout to prompt the model for valid JSON, preventing runaway recursion.
- **Scope is limited to non-streaming, whole-body responses.** Contract repair requires buffering the complete response and issuing a second call, which directly contradicts the first-token latency goal of SSE — streaming responses are therefore never contract-repaired.

### 5. Lock-Free Asynchronous SQLite Batch Audit
- Powered by `modernc.org/sqlite` (pure Go, zero CGO). Uses `_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)` for high-throughput single-writer performance.
- HTTP handlers push audit entries (`RequestID`, `RouteTarget`, `Model`, `LatencyMs`, `TTFTMs`, `PIIRedactedCount`, `Status`) into a bounded channel (capacity 10,000) using a non-blocking `select-default` pattern. A dedicated background worker flushes batches by threshold (50 items) or ticker interval.

### 6. Lossless Wire Passthrough
- Neither direction is ever rebuilt from a typed struct: the gateway rewrites only the fields it actually owns (`model` aliasing, redacted text) and forwards everything else verbatim (`tools`, `tool_choice`, `top_p`, `presence_penalty`, `seed`, vendor extensions). On the egress side placeholders are restored directly on the raw bytes instead of decode-into-struct-then-re-encode.
- As a result `tools` / `tool_calls` / `reasoning_content` (DeepSeek-style reasoning models) / `logprobs` / multimodal `content` arrays all pass through intact, so tool-calling and vision clients need no adaptation.
- Numbers are carried as `json.Number`, so integer literals such as `created` are never reformatted into scientific notation by a float64 round trip. Multimodal `content` arrays are masked part-by-part: only `text` blocks are redacted, image/audio payloads are forwarded untouched.

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
  write_timeout_ms: 120000
  # SSE only: streams are bounded by idle time, not total duration, so slow
  # local models can keep producing tokens for as long as they need.
  stream_idle_timeout_ms: 300000

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

## Endpoints & Ecosystem Integration

EdgeCat is wire-compatible with the **OpenAI ChatCompletion Protocol** for chat and tool-calling semantics, allowing zero-code drop-in proxying:
- **`POST /v1/chat/completions`**: Supports standard JSON responses and low-latency SSE streaming (`stream: true`).
- **Protocol coverage**: `tools` / `tool_choice` / `tool_calls` / `reasoning_content` / multimodal `content` arrays / `temperature` / `top_p` / `max_tokens` / `seed` are all forwarded losslessly.
- **Not implemented**: `/v1/embeddings`, `/v1/completions`, `/v1/responses` (these return 404).
- **`GET /health`**: Returns real-time health metrics, active concurrency slots, fallback statistics, and audit pipeline throughput.
- **`GET /v1/models`**: Provides OpenAI-compatible model catalog discovery.

> 💡 **Architecture Decision Records & Roadmap**:
> - [ADR-0001: Adoption of OpenAI-Compatible Wire Protocol](docs/adr/0001-openai-wire-protocol.md) (Wire Protocol vs. OpenAPI/Swagger disambiguation)
> - [ADR-0002: Product Positioning, Homelab LAN Sharing & Threat Model](docs/adr/0002-positioning-and-homelab-governance.md) ("Gateway as Core, Hub as Usage", NAS LAN sharing boundaries, and zero-disk PII threat model)
> - [EdgeCat Requirements Backlog & Evolution Roadmap](docs/roadmap.md) (Completed Phase 1.5 core, Phase 2 LAN sub-token/cloud-fallback quota specifications, and 5 open design constraints to resolve before coding)

---

## Deployment Topologies & Security Model

Guided by the principle that **"the gateway is the core, while a 'Personal AI Hub' is a usage pattern"**, EdgeCat focuses strictly on horizontal streaming governance across two primary topologies (**do not expose directly to the public internet without TLS and authentication**):

1. **Localhost Developer Sidecar**  
   Runs on `127.0.0.1:8080` as the local runtime companion for **PatchCat** (visual DAG workflow orchestrator), IDE coding assistants, and CLI agents. Workflows are shared via stateless PatchCat DAG JSON definitions rather than exposing live server endpoints.
2. **Homelab / Small-Team LAN Gateway (NAS / Home Server)**  
   Runs as a ~12MB static binary on a home NAS, Mac mini, or router to serve 2–3 people across multiple devices on a trusted local network:
   - **Centralized Cloud Key Vaulting** (Phase 2): Master Cloud API Keys remain on the NAS; client devices will use revocable per-device sub-tokens;
   - **Unlimited Free Local Compute, Capped Paid Cloud Fallback** (Phase 2): Local Ollama traffic runs uncapped, while paid cloud fallback calls will be bounded by per-device daily quotas and SQLite attribution to prevent runaway agent loops or browser XSS from draining cloud billing;
   - **Zero-Disk PII Threat Model** (active today): The PII `Vault` is 100% ephemeral and request-scoped in RAM. `audit_logs` stores only operational telemetry (`request_id`, `route_target`, `model`, `latency_ms`, `ttft_ms`, `pii_redacted_count`, `status`)—never raw prompts or plaintext PII, eliminating offline database replica leakage risks.

> ⚠️ **This version has no inbound authentication yet**: it binds `0.0.0.0` by default and must only be used on a trusted LAN. Sub-token auth and the Fail-Closed guard are tracked in [Roadmap Phase 2](docs/roadmap.md).

### Zero-Invasiveness Client Setup:
- **Desktop & Web Clients (Chatbox / Cherry Studio / NextChat)**:
  - API Provider: Select `OpenAI API`
  - Base URL: `http://localhost:8080/v1`
  - API Key: Any value (e.g., `none`)
- **Python (Official `openai` SDK)**:
  ```python
  from openai import OpenAI

  # Simply point Base URL to EdgeCat; zero business code changes required
  client = OpenAI(base_url="http://localhost:8080/v1", api_key="none")

  response = client.chat.completions.create(
      model="gpt-4o-mini",  # Logical model name rewritten dynamically by gateway
      messages=[{"role": "user", "content": "My phone is 13800138000"}],
      stream=True,
  )
  for chunk in response:
      if chunk.choices[0].delta.content:
          print(chunk.choices[0].delta.content, end="", flush=True)
  ```

---

> **About the Author**  
> **Guo Qiang (GuoBug)**, Product Engineer specializing in platform engineering and growth. Currently focused on AI workflow orchestration, DAG state machines, and deterministic system architectures.  
> Open Source & Homepage: [https://github.com/GuoBug](https://github.com/GuoBug) · [https://guobug.github.io](https://guobug.github.io)  
> Inquiries and discussions on workflow engine architecture, topological scheduling, and developer experience are warmly welcomed.
