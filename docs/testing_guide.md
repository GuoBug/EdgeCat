# EdgeCat Testing & Verification Guide

<p align="center">
  <b>English</b> •
  <a href="testing_guide_zh.md">中文</a>
</p>

This guide outlines how developers can test, benchmark, and verify the **EdgeCat** governance gateway across unit tests, lightweight end-to-end mocks, manual cURL commands, and real third-party clients.

---

## Table of Contents
1. [Approach 1: Automated Unit & Integration Tests (Go Test)](#approach-1-automated-unit--integration-tests-go-test)
2. [Approach 2: Full-Stack Mock Demonstration (Mock Upstream + PowerShell)](#approach-2-full-stack-mock-demonstration-mock-upstream--powershell)
3. [Approach 3: Manual Command-Line Verification (cURL / PowerShell)](#approach-3-manual-command-line-verification-curl--powershell)
4. [Approach 4: Real Third-Party Client Integration (Cherry Studio / Chatbox / Python SDK)](#approach-4-real-third-party-client-integration-cherry-studio--chatbox--python-sdk)

---

## Approach 1: Automated Unit & Integration Tests (Go Test)

The fastest and most rigorous verification method. Covers sliding-window PII rehydration, TTFT circuit-breaking fallback, lossless wire passthrough, Fail-Closed LAN guards, multi-device token auth, CORS/Chrome PNA preflight, and dual-track cloud quota enforcement.

### 1. Run All Tests
```bash
go test -v ./...
```

### 2. Targeted Test Runs
- **Phase 2 Features** (Dynamic model catalog, Token Auth, CORS/PNA, Quota Breaker):
  ```bash
  go test -v ./internal/proxy -run "TestProxy_Phase2"
  ```
- **Fail-Closed LAN Guard** (Refusing non-loopback bind without authentication):
  ```bash
  go test -v ./internal/config
  ```
- **Persistent Daily Quota Management**:
  ```bash
  go test -v ./internal/quota
  ```
- **Sliding-Window Token Stitching**:
  ```bash
  go test -v ./internal/filter
  ```
- **Static Code Quality Check**:
  ```bash
  gofmt -l .
  go vet ./...
  ```

---

## Approach 2: Full-Stack Mock Demonstration (Mock Upstream + PowerShell)

No need to install Ollama or spend cloud API credits. The repository bundles `cmd/mock_upstream` (a simulated local LLM engine) and an automated test runner script.

### Step 1: Start the Mock Local Upstream (Terminal 1)
```powershell
go run ./cmd/mock_upstream
```
> Console logs: `[Mock Upstream] Listening on http://127.0.0.1:11434 (Simulating Ollama / vLLM)...`

### Step 2: Start EdgeCat Gateway (Terminal 2)
```powershell
go run ./cmd/edgecat -config configs/edgecat.example.yaml
```
> Console prints EdgeCat banner, initializing local/cloud tiers, SQLite WAL audit logger, and quota manager.

### Step 3: Run the Verification Script (Terminal 3)
```powershell
.\scripts\test_gateway.ps1
```

#### What You Will Observe:
1. **Health Check**: Connects to `/health`, inspecting local slots and audit throughput.
2. **Non-Streaming PII Redaction**: Sends phone & email; Terminal 1 receives redacted tokens (`{{EC_PII_PHONE_1}}`), while Terminal 3 receives the answer with original plaintext restored!
3. **Real-time SSE Streaming**: Verifies typewriter-style token delivery with cross-chunk rehydration.
4. **SQLite WAL Verification**: Inspects background-flushed audit entries.

---

## Approach 3: Manual Command-Line Verification (cURL / PowerShell)

With EdgeCat running, you can inspect individual mechanisms using `curl.exe`:

### 1. Dynamic Model Discovery (Shielding Physical Names)
```powershell
curl.exe -s http://127.0.0.1:8080/v1/models
```
**Expected**: Returns logical model aliases (`default`, `gpt-4o-mini`, `qwen2.5:7b`), strictly hiding private physical backend paths.

### 2. Chrome Private Network Access (PNA) Preflight
```powershell
curl.exe -i -X OPTIONS http://127.0.0.1:8080/v1/chat/completions `
  -H "Origin: https://patchcat.dev" `
  -H "Access-Control-Request-Method: POST" `
  -H "Access-Control-Request-Private-Network: true"
```
**Expected**: Returns `204 No Content` with headers:
- `Access-Control-Allow-Origin: https://patchcat.dev`
- `Access-Control-Allow-Private-Network: true`

### 3. Check `/health` Multi-Device Quota Summary
```powershell
curl.exe -s http://127.0.0.1:8080/health
```
**Expected**: Returns `clients_usage` showing today's cloud calls, limits, remaining quotas, and `next_quota_reset`.

---

## Approach 4: Real Third-Party Client Integration (Cherry Studio / Chatbox / Python SDK)

EdgeCat serves as a drop-in replacement for OpenAI endpoints:

### 1. Desktop Clients (Chatbox / Cherry Studio / NextChat)
- **API Provider**: `OpenAI API`
- **Base URL**: `http://127.0.0.1:8080/v1`
- **API Key**:
  - If `auth.enabled: true`, use the client's token from `configs/edgecat.example.yaml` (e.g. `ec-dev-token-abc`);
  - If auth is disabled, enter any string (e.g. `none`).
- **Model**: `default` or `gpt-4o-mini`.

### 2. Official Python SDK
```python
from openai import OpenAI

# Direct client to the local EdgeCat gateway
client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="ec-dev-token-abc"  # or "none" if auth is disabled
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "user", "content": "My phone is 13800138000. Please confirm you received it."}
    ],
    stream=True
)

for chunk in response:
    if chunk.choices and chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
print()
```
