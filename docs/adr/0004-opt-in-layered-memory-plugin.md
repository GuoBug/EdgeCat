# ADR-0004: Opt-In Layered Memory Plugin & Cross-Request HMAC Stable PII Keys (R3.2)

<p align="center">
  <b>English</b> •
  <a href="0004-opt-in-layered-memory-plugin_zh.md">中文</a>
</p>

- **Status**: Accepted & Implemented (`R3.2`)
- **Date**: 2026-11-20
- **Author**: Guo Qiang (GuoBug)
- **Affected Modules**: `internal/memory/plugin.go`, `internal/filter/pii.go`, `internal/config/config.go`, `internal/proxy/handler.go`, `cmd/edgecat/main.go`

---

## 1. Context

In [ADR-0002](0002-positioning-and-homelab-governance.md), EdgeCat established two strict architectural constraints for any stateful memory capability:
1. **Never break `CGO_ENABLED=0`**: No C++ tokenizers, no `mattn/go-sqlite3`, and no SQLCipher.
2. **Never persist raw plaintext PII**: Memory must be opt-in (disabled by default), strictly isolated per client namespace in homelab/LAN deployments, and built as a `RequestMutator` plugin ([ADR-0003](0003-two-stage-request-mutator.md)) rather than hardcoded into the proxy hot loop.

To validate `RequestMutator` in practice and provide a production-ready reference plugin for homelab users, **R3.2** implements an opt-in layered memory plugin (`internal/memory`) plus optional cross-request stable PII keys (`filter.NewStableVault`).

---

## 2. Architecture Decisions

### 2.1 Dual SQLite Handles (Writer / Reader Pool Separation)
Sharing a single `MaxOpenConns(1)` SQLite connection between background writes and hot-path `StagePreMask` retrieval would serialize every incoming chat request behind write transactions.
- **Decision**: Open two distinct handles against the same WAL-mode database (`data/edgecat_memory.db`):
  - `writerDB`: `journal_mode(WAL)`, `synchronous(NORMAL)`, `MaxOpenConns(1)` — serializes mutations (`AddFact`, `AddShortTerm`, `PurgeExpired`) without `SQLITE_BUSY` contention.
  - `readerDB`: `journal_mode(WAL)`, `query_only(ON)`, `MaxOpenConns(4)` (configurable via `memory.reader_max_open_conns`) — serves concurrent `StagePreMask` lookups without blocking behind writes.

### 2.2 Pure-Go CJK Full-Text Search (`FTS5` + `tokenize='trigram'`)
Standard SQLite FTS5 `unicode61` cannot segment continuous Chinese sentences without whitespace.
- **Decision**: Use SQLite's built-in `tokenize='trigram'` on `memory_facts_fts` (fully supported in pure-Go `modernc.org/sqlite` with `CGO_ENABLED=0`), kept in sync via SQLite `AFTER INSERT / UPDATE / DELETE` triggers.
- **Query Adaptation**: Continuous CJK user prompts are decomposed into bounded sliding 3-rune windows (capped at 12 terms, double-quoted to prevent FTS5 syntax injection) and joined with `OR` for BM25 ranking. Queries shorter than 3 runes (e.g., `"Go"`) automatically fall back to a parameterized `LIKE` scan scoped to `client_name`.

### 2.3 Layered Storage, Mandatory Namespace Isolation & HMAC Stable PII Keys
- **Two Memory Layers**:
  1. `memory_facts`: Long-term distilled non-PII facts indexed by FTS5 `trigram`.
  2. `memory_short_term`: Rolling short-term summaries bounded by `expires_at` Unix timestamps (`PurgeExpired` reclaims expired rows).
- **Mandatory `client_name` Partitioning**: Every read and write query is strictly scoped by `client_name` (`WHERE client_name = ?`). In multi-device LAN sharing, `alice` can never retrieve `bob`'s facts or short-term context.
- **Zero-Plaintext-PII Persistence & Stable Keys**:
  - Before writing to `memory_facts` or `memory_short_term`, text passes through `filter.Masker`.
  - When `filter.hmac_secret` is configured, `filter.NewStableVault` derives deterministic placeholders from the first 8 bytes (16 lowercase hex chars) of `HMAC-SHA256(original, secret)`: `{{EC_PII_<TYPE>_<16hex>}}`.
  - The same sensitive entity maps to the exact same placeholder across separate requests and across memory storage, while `SlidingRehydrator` seamlessly rehydrates split 16-hex placeholders over SSE.

---

## 3. Configuration & Hot-Path Safety

`memory.enabled` defaults to **`false`** — zero files are opened and zero mutators are registered unless explicitly opted in:

```yaml
filter:
  enabled: true
  hmac_secret: "${EDGECAT_PII_HMAC_SECRET}" # Optional: enables cross-request HMAC-SHA256 stable PII keys

memory:
  enabled: true
  sqlite_path: "data/edgecat_memory.db"
  max_facts: 5
  max_short_term: 3
  query_timeout_ms: 50
  reader_max_open_conns: 4
```

- **Fail-Open TTFT Protection**: `MutatePreMask` runs under a strict `context.WithTimeout(ctx, queryTimeout)` (default `50ms`). If retrieval times out or errors, the plugin logs a warning and returns `nil` so chat inference is never blocked.
- **Pre-Mask PII Governance**: Injected `[EdgeCat Memory Context]` system messages run in `StagePreMask`, meaning they are still audited/masked by EdgeCat's PII policy before reaching upstream models.

---

## 4. Trade-Offs & Boundaries

- **3-Character Trigram Floor**: SQLite's `trigram` tokenizer matches substrings of length ≥ 3; 2-character Chinese words embedded inside a longer sentence require either a 3-character overlap or a short exact query (which uses the `LIKE` fallback).
- **Distillation Is Caller/External Responsibility**: Consistent with EdgeCat's non-goals, the plugin does not spawn extra LLM calls inside the proxy hot loop to auto-distill conversations; facts and short-term summaries are written explicitly via `AddFact` / `AddShortTerm` (e.g., from an offline background job or local worker).
- **Offline Copy Threat Model**: As documented in [ADR-0002](0002-positioning-and-homelab-governance.md), `memory.db` is unencrypted SQLite (preserving `CGO_ENABLED=0` and FTS5); safety relies on never persisting plaintext PII rather than full-database encryption.
