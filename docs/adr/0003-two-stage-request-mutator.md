# ADR-0003: Two-Stage `RequestMutator` Inbound Extension Hook (R3.1)

<p align="center">
  <b>English</b> •
  <a href="0003-two-stage-request-mutator_zh.md">中文</a>
</p>

- **Status**: Accepted & Implemented (`R3.1`)
- **Date**: 2026-11-19
- **Author**: Guo Qiang (GuoBug)
- **Affected Modules**: `internal/proxy/mutator.go`, `internal/proxy/protocol.go`, `internal/proxy/handler.go`

---

## 1. Context

In [ADR-0002](0002-positioning-and-homelab-governance.md), EdgeCat committed to remaining a deterministic, stateless inference governance gateway rather than absorbing stateful product features (such as long-term memory, custom prompt routers, or domain-specific policy engines) into its core loop.

At the same time, real-world deployments (and future opt-in examples such as **R3.2 Layered Memory Plugin**) need a clean, zero-invasiveness way to:
1. Inject system context or retrieved facts into inbound requests before they reach upstream models;
2. Rewrite logical model aliases or tune inference parameters per client/header;
3. Enforce custom admission or rejection policies (with OpenAI-compatible error envelopes) before consuming local concurrency slots or paid cloud quotas.

A naive single-stage hook placed at the wrong point in `handleChatCompletions` creates severe security or usability flaws:
- Placing a hook **only after PII masking** means any text injected by a plugin (e.g., retrieved memory facts) would bypass EdgeCat's PII masker and risk leaking sensitive data to Cloud Tier.
- Placing a hook **only before PII masking** means a plugin cannot inspect `PIIRedactedCount` or apply post-redaction routing constraints (e.g., forcing `LocalOnly` or rejecting requests that exceed a redaction budget).

---

## 2. Decision: Two-Stage Inbound Pipeline (`StagePreMask` + `StagePostMask`)

We introduce a two-stage `RequestMutator` interface in `internal/proxy/mutator.go` executed sequentially in registration order across two strict governance boundaries:

```
POST /v1/chat/completions
  │
  ▼
ParseRequest (lossless map[string]any + json.Number)
  │
  ▼
[Stage 1: StagePreMask]   ──► Inject prompts/facts, rewrite logical model, adjust PIIPolicy, or reject
  │
  ▼
PII Policy Evaluation & Eager Masking (block / local_only / mask_on_egress / mask_always)
  │
  ▼
[Stage 2: StagePostMask]  ──► Inspect PIIRedactedCount, tighten LocalOnly / QueueWaitMs, or reject
  │
  ▼
Routing Admission (DecideRouteWithContext) & Local/Cloud Dispatch
```

### Core Contract
- **Interface**: `RequestMutator` defines `Name() string`, `MutatePreMask(ctx, req, meta) error`, and `MutatePostMask(ctx, req, meta) error`. Single-stage plugins can use `PreMaskMutatorFunc`, `PostMaskMutatorFunc`, or `MutatorFuncs` without boilerplate.
- **Registration**: Attached via `proxy.WithRequestMutators(...)` on `NewHandler(...)` or dynamically via `handler.UseMutator(...)` (protected by `sync.RWMutex`, nil-safe).
- **Per-Request Scratchpad**: `RequestMeta.Values` (`map[string]any`) allows mutators to pass state from `StagePreMask` to `StagePostMask` without polluting the wire JSON payload.
- **Lossless Request Helpers**: `*Request` exposes `SetLogicalModel` (updating both `logicalModel` for cloud fallback mapping and the wire `"model"` field), `Get` / `Set` / `Delete`, `SetMessages`, `PrependSystemMessage`, and `AppendMessage` while preserving `json.Number` and vendor extensions.
- **Structured Rejection**: Returning a `*MutatorError` aborts upstream dispatch and writes the exact HTTP status and OpenAI error envelope; returning any plain `error` defaults to `400 Bad Request` (`code: "mutator_rejected"`). All rejections are logged to SQLite `audit_logs` with `route_target = "blocked"`.
- **Observability**: `GET /admin/status` exposes `"mutators": [...]` listing registered mutators in execution order.

---

## 3. Security Invariants

1. **Pre-Mask Injection Is Always Governed**: Any text added in `StagePreMask` (e.g., via `req.PrependSystemMessage`) passes through PII policy evaluation (`block`, `local_only`, `mask_always`, `mask_on_egress`) before leaving the gateway.
2. **Monotonic `LocalOnly` Escalation**: Once PII `local_only` policy sets `localOnly = true`, `StagePostMask` mutators may tighten routing (`meta.LocalOnly = true`), but **cannot** downgrade it back to `false` (`localOnly = localOnly || meta.LocalOnly`).
3. **Fail-Safe PII Policy Normalization**: If a `StagePreMask` mutator writes an unrecognized value into `meta.PIIPolicy`, the gateway falls back to `"mask_always"`.
4. **Zero-Allocation Default Fast Path**: When no mutators are registered, `handleChatCompletions` skips header cloning and `RequestMeta` allocation entirely.

---

## 4. Usage Example

```go
handler := proxy.NewHandler(
    cfg, masker, r, guard, auditLogger, quotaMgr,
    proxy.WithRequestMutators(
        proxy.PreMaskMutatorFunc("system-context", func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
            if meta.ClientName == "workstation" {
                req.PrependSystemMessage("Always respond concisely in Chinese.")
            }
            return nil
        }),
        proxy.PostMaskMutatorFunc("pii-budget", func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
            if meta.PIIRedactedCount > 5 {
                return &proxy.MutatorError{
                    StatusCode: http.StatusForbidden,
                    Type:       "policy_error",
                    Code:       "pii_budget_exceeded",
                    Message:    "too many sensitive entities in a single request",
                }
            }
            return nil
        }),
    ),
)
```

---

## 5. Consequences & Trade-Offs

### Positive
- Keeps EdgeCat's core binary lean (`CGO_ENABLED=0`, zero external dependencies) while providing a clean, testable extension seam for **R3.2** (opt-in memory plugin) and custom enterprise/homelab policies.
- Preserves lossless wire passthrough and strict PII safety boundaries by construction.

### Costs & Boundaries
- **Synchronous Latency Budget**: Mutators execute synchronously on the inbound hot path before routing. Slow I/O inside a mutator directly adds to TTFT; plugins doing storage lookups (such as R3.2) must bound their own timeouts via `ctx` and use dedicated read pools.
- **Inbound-Only Scope**: `RequestMutator` intentionally does not mutate outbound SSE chunks to preserve deterministic sliding-window PII rehydration and low first-token latency.
- **No Dynamic Script / Shell Execution**: Consistent with EdgeCat's explicit non-goals, mutators are compiled Go interfaces—not arbitrary runtime shell/MCP hooks.
