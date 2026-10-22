# EdgeCat Requirements Backlog & Evolution Roadmap

<p align="center">
  <b>English</b> •
  <a href="roadmap_zh.md">中文</a>
</p>

This document tracks **EdgeCat**'s product positioning, completed architectural milestones, prioritized engineering backlog, and explicit non-goals. All development aligns around **a deterministic, local-first AI inference governance gateway designed for solo workstations, homelab/small-team LAN sharing, and PatchCat sidecar pairing**.

---

## 1. Core Positioning & Target Scenarios

1. **Localhost Developer Sidecar**: Runs on `127.0.0.1:8080` to govern local IDE extensions, CLI agents, and the **PatchCat** visual DAG orchestrator with local-first routing and streaming PII redaction.
2. **Homelab / Small-Team LAN Governance Gateway**: Deployed on a home NAS, Mac mini, or router to serve 2–3 people across multiple devices on a trusted local network:
   - **Centralized Cloud API Key Vaulting**: Master cloud keys stay on the NAS; devices authenticate with lightweight per-device sub-tokens.
   - **Unified Outbound Privacy Guard**: Phone numbers, emails, private IPv4 addresses, and secret keys from any LAN device are masked into deterministic placeholders before leaving the home/studio network and rehydrated over SSE on return.
   - **Unlimited Free Local Compute + Capped Paid Cloud Fallback**: Local Ollama/vLLM inference is unlimited; fallback calls to paid cloud tiers are strictly bounded by per-device daily quotas (`daily_cloud_limit`) to prevent runaway agent loops or browser XSS from draining cloud billing.
   - **Per-Device Audit Attribution**: Track local vs. cloud fallback usage and latency per device in SQLite.

---

## 2. Phased Engineering Backlog

### ✅ Phase 1 & 1.5: Deterministic Streaming Governance & Lossless Wire Core (Completed)

| ID | Module | Engineering Specification & Acceptance Criteria | Status |
| :--- | :--- | :--- | :---: |
| **R1.1** | **Sliding-Window SSE Rehydration** | Inbound regex masking into a per-request in-memory `Vault`; outbound dual-cursor buffer stitches `{{EC_PII_...}}` tokens split across SSE chunks. | ✅ Done |
| **R1.2** | **Concurrency Semaphore & Pre-Header TTFT Fallback** | Channel semaphore (`max_concurrent_local`) + independent TTFT watchdog; silently reroutes to Cloud Tier before HTTP headers are flushed on saturation or timeout. | ✅ Done |
| **R1.3** | **Lossless Wire Passthrough (`internal/proxy/protocol.go`)** | Decodes requests via `map[string]any` + `json.Number` to preserve `tools`, `tool_choice`, `top_p`, `seed`, and vendor extensions while keeping the original logical model immutable for fallback resolution; restores PII directly on raw response bytes to preserve `tool_calls` and `reasoning_content`. | ✅ Done |
| **R1.4** | **Multimodal & Tool Argument Redaction** | Supports both string and multimodal array shapes in `messages[].content` (redacting `type=="text"` parts while passing image/audio payloads untouched); masks `tool_calls[].function.arguments`. | ✅ Done |
| **R1.5** | **Rolling SSE Idle Deadline (`stream_idle_timeout_ms`)** | Uses `http.ResponseController.SetWriteDeadline` refreshed on each SSE flush (default 300s) so slow local models can stream long outputs without hitting fixed `WriteTimeout`. | ✅ Done |
| **R1.6** | **Strict JSON Contract Guard (`strict_json_enabled`)** | Master config switch + per-request opt-in (`response_format` or `X-EdgeCat-Strict-JSON: true`) for non-streaming responses; strips code fences and executes at most 1 bounded repair call. | ✅ Done |
| **R1.7** | **Lock-Free Async SQLite Batch Audit** | Pure-Go `modernc.org/sqlite` (`CGO_ENABLED=0`) in WAL mode; non-blocking bounded channel with single background batch writer. | ✅ Done |

---

### 🚧 Phase 2: Homelab / Small-Team LAN Sharing & PatchCat Sidecar Security (Next Up)

> **Goal**: Enable safe multi-device LAN sharing on a NAS/home server and browser-based PatchCat pairing with zero UI bloat.

| ID | Feature | Detailed Engineering Specification | Priority |
| :--- | :--- | :--- | :---: |
| **R2.1** | **Secure-by-Default & Fail-Closed LAN Guard** | 1. Tighten default `server.host` to `"127.0.0.1"`.<br>2. **Startup Fail-Closed Check**: When `server.host` is bound to a non-loopback address (e.g., `"0.0.0.0"` or LAN IP) and `auth.enabled` is false (or no client tokens are configured), refuse startup with an actionable error unless `allow_insecure_lan: true` is explicitly set. | **P0** |
| **R2.2** | **Per-Device Sub-Token Authentication (`auth.clients`)** | 1. Configure named client tokens in `edgecat.yaml` (`name`, `token`).<br>2. Validate `Authorization: Bearer <token>` using constant-time comparison (`subtle.ConstantTimeCompare`); return `401 Unauthorized` on mismatch.<br>3. Keep `GET /health` accessible for liveness checks without leaking sensitive secrets. | **P0** |
| **R2.3** | **Dual-Track Quota: Unlimited Local, Capped Cloud (`daily_cloud_limit`)** | 1. Support per-client `daily_cloud_limit` (`0` = unlimited, `-1` = local-only / cloud forbidden, `>0` = max daily cloud calls).<br>2. **Core Invariant**: Requests served by the free **Local Tier** consume zero quota. Quota is checked and atomically incremented only when dispatching or falling back to the paid **Cloud Tier** (auto-resetting daily).<br>3. Return `429 Too Many Requests` when a client's daily cloud fallback quota is exhausted. | **P0** |
| **R2.4** | **Controlled CORS & Chrome PNA Preflight** | 1. Configure `server.allowed_origins` allowlist (e.g., `https://patchcat.dev`, `http://localhost:5173`).<br>2. Handle `OPTIONS` preflight requests (`204 No Content`).<br>3. Support Chrome Private Network Access: respond with `Access-Control-Allow-Private-Network: true` when `Access-Control-Request-Private-Network: true` is present, allowing HTTPS web apps to reach LAN/localhost EdgeCat instances safely. | **P1** |
| **R2.5** | **Per-Client SQLite Audit Attribution** | 1. Add `client_name TEXT NOT NULL DEFAULT 'anonymous'` to `audit_logs` (with idempotent startup schema migration for existing DBs).<br>2. Expose per-client daily local/cloud counters and remaining cloud quota in `GET /health`. | **P1** |

#### Design Constraints to Resolve Before Phase 2

> The following 5 items were raised by a **DeepSeek cross-review** (2026-10-22). They are not yet folded into the acceptance criteria above; each needs a decision before implementation starts, or the work will be re-done.

| # | Open Question | Recommended Resolution | Affects |
| :--- | :--- | :--- | :--- |
| **D1** | **Quota check timing**: for streaming requests the fallback happens after `tryLocalStream` fails but before SSE headers are written. If quota is evaluated after the headers, a `429` can no longer be delivered | Insert the quota check between "local failed" and "call cloud", strictly before `WriteHeader` — that is the only rejection window | R2.3 |
| **D2** | **Quota counter durability**: an in-memory atomic counter resets to zero on restart, and NAS boxes reboot — so the daily quota can be bypassed by restarting the process | Persist daily counters in SQLite (one row per client per day) and load on startup; keep memory only as a hot-path cache | R2.3 / R2.5 |
| **D3** | **Failure semantics of `daily_cloud_limit: -1`**: what to return when the local tier is unavailable and the client is forbidden from using cloud | Return `503 Service Unavailable` with an explicit message (local unavailable and cloud fallback disabled for this client), not a generic `429` | R2.3 |
| **D4** | **Quota day boundary timezone**: reset at UTC midnight or server-local midnight | Use server-local time (what homelab users expect) and expose the next reset timestamp in `/health` | R2.3 |
| **D5** | **`/v1/models` is still hardcoded**: it returns three fixed model names, so multi-device clients (Cherry Studio et al.) cannot discover the logical models configured on this gateway, while physical model names leak | Derive the logical model list from the keys of `local.model_mapping` / `cloud.model_mapping`; never expose physical names via discovery | Phase 2 prerequisite (multi-device usability) |

---

### 🔭 Phase 3: Extensibility Hooks & Production Telemetry (Future Backlog)

| ID | Feature | Detailed Engineering Specification | Priority |
| :--- | :--- | :--- | :---: |
| **R3.1** | **`RequestMutator` Extension Hook** | Define a clean pre-routing request mutator interface in `internal/proxy` for opt-in plugins. | **P2** |
| **R3.2** | **Opt-In Layered Memory Plugin Example** | Built strictly as an optional `RequestMutator` example (disabled by default):<br>1. Separate SQLite Writer (`MaxOpenConns(1)`) and Reader pools.<br>2. Use `tokenize='trigram'` for CJK full-text search.<br>3. Store only distilled non-PII facts (`Facts`), isolate namespaces by `client_name`, and use `HMAC-SHA256` stable keys if cross-request PII references are required. | **P3** |
| **R3.3** | **90-Day Homelab Telemetry Case Study** | Run EdgeCat + PatchCat continuously on a personal workstation/NAS and publish empirical metrics on local 7B offload ratio, TTFT fallback frequency, and cloud cost savings. | **P2** |

---

## 3. Explicit Non-Goals

To preserve EdgeCat's small footprint and deterministic guarantees, the following are **explicitly out of scope**:
1. ❌ **No CGO Dependencies**: No `mattn/go-sqlite3`, SQLCipher, or C++ tokenizers that break `CGO_ENABLED=0` static builds.
2. ❌ **No Public Multi-Tenant Billing SaaS**: No payment gateways, user registration portals, or public runtime sharing. Workflows are shared via stateless **PatchCat DAG JSON** files.
3. ❌ **No Inline MCP / Shell Execution in the Proxy Loop**: EdgeCat does not intercept `tool_calls` to execute arbitrary local shell scripts inside the streaming proxy path; it losslessly proxies and redacts tool definitions and arguments.
