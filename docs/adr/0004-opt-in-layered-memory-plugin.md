# ADR-0004: Opt-In Layered Memory Plugin, Governed Lifecycle & Prefix-Cache Two-Zone Injection (R3.2 / R3.2.1)

<p align="center">
  <b>English</b> •
  <a href="0004-opt-in-layered-memory-plugin_zh.md">中文</a>
</p>

- **Status**: Accepted & Implemented (`R3.2`, evolved in `R3.2.1`)
- **Date**: 2026-11-20 (Updated: 2026-11-25 for `R3.2.1`)
- **Author**: Guo Qiang (GuoBug)
- **Affected Modules**: `internal/memory/plugin.go`, `internal/proxy/protocol.go`, `internal/filter/pii.go`, `internal/config/config.go`, `internal/proxy/handler.go`, `cmd/edgecat/main.go`

---

## 1. Context

In [ADR-0002](0002-positioning-and-homelab-governance.md), EdgeCat established two strict architectural constraints for any stateful memory capability:
1. **Never break `CGO_ENABLED=0`**: No C++ tokenizers, no `mattn/go-sqlite3`, and no SQLCipher.
2. **Never persist raw plaintext PII**: Memory must be opt-in (disabled by default), strictly isolated per client namespace in homelab/LAN deployments, and built as a `RequestMutator` plugin ([ADR-0003](0003-two-stage-request-mutator.md)) rather than hardcoded into the proxy hot loop.

**R3.2** delivered the initial dual-pool SQLite FTS5 layered memory plugin (`internal/memory`) and cross-request HMAC stable PII keys (`filter.NewStableVault`). **R3.2.1** evolves this plugin with governed memory lifecycle primitives inspired by Mirabase, addressing three concrete production bottlenecks without relaxing any EdgeCat invariant:
1. **Prefix-Cache busting in multi-turn conversations** when dynamic retrieval results were prepended at `messages[0]`.
2. **Stale/duplicate fact accumulation** when facts evolve over time without temporal supersede pointers.
3. **Unbounded context noise & read/write contention** when tracking hit statistics or retiring cold/unanchored facts.

---

## 2. Architecture Decisions

### 2.1 Dual SQLite Handles & Idempotent Schema Evolution
Sharing a single `MaxOpenConns(1)` SQLite connection between background writes and hot-path `StagePreMask` retrieval would serialize every incoming chat request behind write transactions.
- **Dual-Pool Separation**:
  - `writerDB`: `journal_mode(WAL)`, `synchronous(NORMAL)`, `MaxOpenConns(1)` — serializes mutations (`AddFact`, `SupersedeFact`, `SweepDormantUnused`, `MarkQuoteMissing`, `WakeFact`, `AddShortTerm`, `PurgeExpired`, and batched hit flushes) without `SQLITE_BUSY` contention.
  - `readerDB`: `journal_mode(WAL)`, `query_only(ON)`, `MaxOpenConns(4)` (configurable via `memory.reader_max_open_conns`) — serves concurrent `StagePreMask` lookups strictly read-only.
- **Idempotent Migration (`R3.2.1`)**: On startup, `initMemorySchema` inspects `PRAGMA table_info(memory_facts)` and applies idempotent `ALTER TABLE memory_facts ADD COLUMN` statements (`pinned`, `valid_to`, `superseded_by`, `dormant_reason`, `source_quote`, `last_served_at`, `served_count`, `created_at_unix`) so existing `R3.2` databases upgrade seamlessly in place. The `memory_facts_au` FTS5 trigger is scoped to `AFTER UPDATE OF fact, tags` so metadata updates and hit-counter flushes avoid redundant trigram re-tokenization.

### 2.2 Pure-Go CJK Full-Text Search (`FTS5` + `tokenize='trigram'`)
Standard SQLite FTS5 `unicode61` cannot segment continuous Chinese sentences without whitespace.
- **Decision**: Use SQLite's built-in `tokenize='trigram'` on `memory_facts_fts` (pure-Go `modernc.org/sqlite`, preserving `CGO_ENABLED=0`).
- **Query Adaptation**: Continuous CJK user prompts are decomposed into bounded sliding 3-rune windows (capped at 12 terms, double-quoted against FTS5 syntax injection) and joined with `OR` for BM25 ranking. Queries shorter than 3 runes (e.g., `"Go"`) fall back to a parameterized `LIKE` scan scoped to `client_name`.

### 2.3 Prefix-Cache Friendly Two-Zone Context Injection (`R3.2.1`)
Prepending query-dependent retrieval results at `messages[0]` mutates the leading token sequence on every turn, invalidating KV / Prefix Caches across local engines (Ollama, `llama.cpp`, vLLM) and cloud APIs (OpenAI, DeepSeek).
- **Zone 1 — Deterministic Static Prefix (`messages[0]`)**:
  - Queries active `pinned = 1` facts for `client_name` (`valid_to IS NULL AND superseded_by IS NULL AND dormant_reason = ''`), ordered strictly by `id ASC` and capped by `memory.max_pinned_facts` (default `10`).
  - Rendered deterministically as `[EdgeCat Pinned Rules]` via `Request.PrependSystemMessage`, producing byte-identical prefix tokens across turns as long as the pinned rule set does not change.
- **Zone 2 — Dynamic Tail Context (Before Last User Turn)**:
  - Queries active unpinned facts (`pinned = 0`, preventing duplicate quota consumption with Zone 1) via `SearchFacts` plus unexpired `ListShortTerm` summaries, rendered as `[EdgeCat Dynamic Context]`.
  - Injected via `Request.InsertSystemBeforeLastUser` as a `role: "system"` message immediately preceding the last `role == "user"` message (or appended at the end if no `user` message exists). In a multi-turn conversation `[system, user1, assistant1, user2]`, the outbound sequence becomes `[PinnedRules, system, user1, assistant1, DynamicContext, user2]`, keeping `messages[0..3]` (and any tool definitions) 100% byte-invariant across follow-up questions.
- **Diagnostics**: `meta.Values` records `memory_pinned_injected`, `memory_facts_injected`, and `memory_short_term_injected` per request.

### 2.4 Temporal Supersede Chains, Idempotent Deduplication & Lineage Resolution (`R3.2.1`)
- **Idempotent `AddFact` / `AddFactWithMeta`**: Checks whether an active (`valid_to IS NULL AND superseded_by IS NULL`) row with identical sanitized `fact` text already exists under the same `client_name`. If found, returns the existing `id` without duplicating rows (promoting `pinned = 1`, waking dormant status, or updating `source_quote` when requested).
- **Atomic `SupersedeFact`**: Inside a single `writerDB` transaction, verifies `oldID` belongs to `client_name` (`ErrFactNotFound` on missing or cross-client IDs) and is not yet superseded (`ErrFactConflict` to prevent branching chains), inserts the sanitized replacement fact, and stamps `valid_to = now, superseded_by = newID` on `oldID`.
- **Lineage-Aware `SearchFacts` ("Search Old Term, Serve New Value")**: When a user prompt lexically hits a historical superseded row (`superseded_by IS NOT NULL`), `SearchFacts` traverses `superseded_by` forward up to `maxSupersedeHops = 5` (with cycle detection and per-hop `WHERE client_name = ?` verification), returning the current active unpinned successor deduplicated by `id`.

### 2.5 Lock-Free Hit Tracking, Dormancy & Quote Guard (`R3.2.1`)
- **Async Non-Blocking Hit Tracker**: `MutatePreMask` never writes to SQLite. Injected fact IDs (Zone 1 + Zone 2) are pushed via non-blocking `select` to a bounded channel (default capacity `256`). A single background goroutine coalesces per-fact increments and flushes `served_count` and monotonic `last_served_at` batches through `writerDB`, draining cleanly on `Close()`. When the channel is full, counter updates are dropped immediately (`DroppedHitCount`) rather than stalling inference.
- **Maintenance Primitives**:
  - `SweepDormantUnused(ctx, maxIdle)`: Marks `pinned = 0` active facts idle beyond `maxIdle` (`COALESCE(last_served_at, created_at_unix)`) as `dormant_reason = 'unused'`. `pinned = 1` facts are permanently exempt.
  - `MarkQuoteMissing(ctx, clientName, factID)`: Marks `pinned = 0` facts belonging to `clientName` as `dormant_reason = 'quote_missing'` when an external verifier detects source drift.
  - `WakeFact(ctx, clientName, factID)`: Clears `dormant_reason = ''` and refreshes `last_served_at`, strictly scoped to `clientName`.

### 2.6 Mandatory Namespace Isolation & Zero-Plaintext-PII Persistence
- Every read, write, supersede, dormancy, and wake SQL statement binds `WHERE client_name = ?`.
- All persisted text fields (`fact`, `tags`, `source_quote`, and short-term `summary`) pass through `sanitizeForStorage` (`filter.Masker` + `filter.NewStableVault` HMAC-SHA256 `{{EC_PII_<TYPE>_<16hex>}}` placeholders) before touching SQLite. When `filter.hmac_secret` is omitted, `memory.Plugin` generates and persists a random 32-byte per-database salt in `memory_meta` so stored placeholders still use 16-hex digests and never collide with request-scoped sequential `{{EC_PII_<TYPE>_1}}` counters during response rehydration.

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
  max_pinned_facts: 10            # Zone 1 static prefix cap (sorted by id ASC at messages[0])
  max_facts: 5                    # Zone 2 dynamic FTS5 retrieval cap
  max_short_term: 3               # Zone 2 rolling short-term summary cap
  query_timeout_ms: 50            # Strict fail-open retrieval timeout budget
  reader_max_open_conns: 4        # Read-only SQLite pool size
  prepend_dynamic_context: false  # Escape hatch for strict templates rejecting mid-chat system roles
```

- **Fail-Open TTFT Protection**: `MutatePreMask` runs under `context.WithTimeout(ctx, queryTimeout)` (default `50ms`) with zero network/LLM calls. Timeouts or SQLite errors log a warning and return `nil`.
- **Pre-Mask PII Governance**: Both `[EdgeCat Pinned Rules]` and `[EdgeCat Dynamic Context]` are injected during `StagePreMask`, so EdgeCat's outbound PII policy still governs the assembled payload before upstream dispatch.

---

## 4. Trade-Offs & Operational Boundaries

- **Mid-Conversation `system` Role Compatibility (`prepend_dynamic_context`)**: Inserting Zone 2 (`role: "system"`) immediately before the latest `user` message preserves historical KV cache blocks across OpenAI, DeepSeek, Qwen, and modern Ollama/`llama.cpp` templates. However, certain strict or legacy chat templates enforce a rigid single-`system`-at-index-0 constraint and reject mid-array `system` roles with HTTP 400. Operators routing to such models can set `memory.prepend_dynamic_context: true` to place Zone 2 at `messages[1]` directly behind Zone 1, trading away multi-turn history Prefix Cache reuse for template compatibility.
- **5-Hop Lineage Traversal Ceiling**: `SearchFacts` caps `superseded_by` forward resolution at `5` hops. If a fact is superseded more than 5 times and the user searches exclusively for vocabulary from generation 1 that no longer appears in generations `N-4..N`, retrieval returns empty rather than performing unbounded pointer chasing on the hot path. Periodic offline consolidation can re-anchor or compact deep chains if needed.
- **Best-Effort Hit Counters Under Extreme Burst**: Because the hit-tracking channel is bounded (`256` events) and non-blocking, sustained bursts exceeding `writerDB` flush throughput drop `served_count` increments rather than slowing down chat responses. Hit counts are governance heuristics for dormancy sweeps, not billing-grade ledgers.
- **3-Character Trigram Floor & External Distillation**: SQLite `trigram` indexes substrings of length >= 3 (short `<3`-rune standalone queries use the `LIKE` fallback). Fact extraction, `SupersedeFact` calls, and `SweepDormantUnused` / `MarkQuoteMissing` schedules remain caller or sidecar responsibilities, keeping the gateway hot loop deterministic and free of extra LLM calls.
- **Offline Copy Threat Model**: Consistent with [ADR-0002](0002-positioning-and-homelab-governance.md), `edgecat_memory.db` is unencrypted SQLite (`CGO_ENABLED=0`); privacy relies on pre-storage PII redaction rather than full-disk/SQLCipher encryption.
