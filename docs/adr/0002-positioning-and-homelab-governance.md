# ADR-0002: Product Positioning, Homelab LAN Sharing & Security Threat Model

<p align="center">
  <b>English</b> •
  <a href="0002-positioning-and-homelab-governance_zh.md">中文</a>
</p>

- **Status**: Accepted
- **Date**: 2026-10-22
- **Author**: Guo Qiang
- **Context Area**: Product Boundaries, LAN Multi-Device Governance, PII Threat Model, Evolution Roadmap

---

## 1. Context and Problem Statement

Following the initial implementation of EdgeCat's streaming governance core, three foundational architectural questions emerged regarding its evolution toward Personal and Edge AI:
1. **Category Definition**: Should EdgeCat remain a focused, stateless "Local-First AI Inference Governance Gateway", or expand into a vertical "Personal AI Hub" bundling long-term memory, cron workers, and management UIs?
2. **Sharing & Pairing Boundaries**: When paired with browser-based workflow orchestrators (such as **PatchCat**) or multiple devices across a household or small studio, how should master Cloud API Keys be protected? Should public internet sharing be supported?
3. **Privacy vs. Persistence Physics**: EdgeCat's PII `Vault` is an ephemeral per-request in-memory map (`{{EC_PII_PHONE_1}}`). How do we reconcile zero-trust privacy and `CGO_ENABLED=0` static compilation with proposals for persistent conversation logs or full-text search?

---

## 2. Decision 1: The Gateway is the Core; the "Hub" is a Usage Pattern

- **Verdict**: **EdgeCat is strictly a horizontal, Local-First AI Inference Governance Gateway—not a vertical all-in-one AI desktop application.**
- **Rationale**:
  1. **Horizontal Primitives vs. Vertical Bloat**: Pre-header TTFT circuit breaking, sliding-window SSE placeholder rehydration, lossless wire passthrough, and lock-free WAL auditing are universal systems primitives applicable to solo workstations, homelab NAS servers, and edge clusters alike. Bundling UIs and installers narrows applicability and dilutes core systems engineering depth.
  2. **Plugin Discipline**: Stateful enhancements (such as context/memory injection) belong strictly as opt-in examples on a `RequestMutator` extension hook rather than mandatory core dependencies.

---

## 3. Decision 2: Target Homelab / Small-Team LAN Sharing; Reject Public Multi-Tenancy

EdgeCat explicitly targets two deployment topologies—**Single-User Localhost** and **Trusted Homelab / Small-Team LAN (NAS / Home Server)**—while rejecting public multi-tenant SaaS hosting:

| Dimension | Public Multi-Tenant Gateway (Non-Goal) | Homelab / Small-Team LAN Gateway (Target) |
| :--- | :--- | :--- |
| **Topology** | Exposed to the public internet for untrusted users | 1 NAS / Mac mini / Router running EdgeCat on LAN, serving 2–3 people across 3–5 devices (Workstation, Mobile, PatchCat Web) |
| **Core Value** | Complex billing, DDoS defense, enterprise RBAC | **Unified master API Key vaulting, shared free local GPU + cloud fallback, unified outbound PII redaction, per-device usage audit** |
| **Workflow Sharing Unit** | Sharing a live runtime URL (billing hazard) | **Sharing stateless workflow definitions (PatchCat DAG JSON without keys)**; recipients connect to their own local EdgeCat |

### Security Model for Gateway-Hosted API Keys:
Hosting the master Cloud API Key inside EdgeCat's local configuration eliminates raw key exposure in browser `localStorage`, though a browser XSS could still use the local sub-token to issue requests. True security comes from three operational controls:
1. **Revocable Per-Device Sub-Tokens**: Each device/client receives an independent token (`ec-workstation`, `ec-ipad`, `ec-patchcat`) that can be revoked independently without rotating upstream cloud keys.
2. **Unlimited Free Local Tier, Capped Paid Cloud Tier (`daily_cloud_limit`)**: Local Ollama inference consumes zero quota; fallback calls to paid Cloud Tiers are bounded by per-token daily quotas so runaway agent loops or compromised client tokens cannot drain cloud billing.
3. **Fail-Closed Non-Loopback Guard**: Default bind is `127.0.0.1`. Binding to `0.0.0.0` or a LAN IP requires explicit token authentication and an origin allowlist (supporting Chrome Private Network Access `Access-Control-Allow-Private-Network: true`).

---

## 4. Decision 3: Threat Model & Storage Layering (Why Full-DB SQLCipher is Rejected)

1. **Physical Incompatibility of Full-DB Encryption with `CGO_ENABLED=0` and FTS5**:
   - `modernc.org/sqlite` is pure Go and does not support SQLCipher. Adopting SQLCipher requires `mattn/go-sqlite3` (CGO), sacrificing single-binary cross-compilation.
   - SQLite FTS5 indexes plaintext tokens; full-database encryption defeats full-text indexing (and Chinese retrieval additionally requires `tokenize='trigram'`).
2. **Realistic Threat Model (Offline Replica Protection)**:
   - On a personal workstation or home NAS, an attacker with local root/process memory access can already dump RAM or read OS keyrings. Encryption only mitigates **offline file leakage** (cloud drive sync, backup disks, hardware repair).
3. **Storage Discipline**:
   - **Default Baseline (Active)**: The PII `Vault` remains **100% in-memory and request-scoped**. `audit_logs` records only metadata (`request_id`, `client_name`, `route_target`, `model`, `latency_ms`, `ttft_ms`, `pii_redacted_count`, `status`)—**never raw conversation payloads or plaintext PII**.
   - **Future Memory Plugin Contract (Phase 3)**: Any opt-in memory plugin must store only distilled non-PII facts (`Facts`), enforce short TTLs on raw context, and replace per-request sequential counters with `HMAC-SHA256(plaintext, local_secret)` stable keys.

---

## 5. Consequences

### Positive:
- **Focused Scope**: A `< 20MB` zero-dependency static binary that solves real homelab/small-team governance problems without UI or multi-tenant bloat.
- **Lossless & Long-Stream Safe**: `internal/proxy/protocol.go` preserves all upstream/downstream extension fields (`tools`, `tool_calls`, `reasoning_content`, multimodal arrays) and replaces fixed write deadlines with rolling SSE idle deadlines (`stream_idle_timeout_ms`).

### Trade-offs & Boundaries:
- EdgeCat is not a public internet API gateway and must not be exposed directly to untrusted networks without TLS termination and token authentication.
