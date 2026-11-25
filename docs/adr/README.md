# Architecture Decision Records (ADR)

This directory documents the critical architectural and engineering decisions made during the evolution of EdgeCat. Each record outlines the context, rationale, trade-offs, and consequences of a significant architectural choice.

For future agents and contributors, review these records before proposing structural or protocol changes.

## Index of Architecture Decision Records

| ADR | Title | Status | Date | Decision Summary |
| :--- | :--- | :--- | :--- | :--- |
| [**0001**](0001-openai-wire-protocol.md) ([中文](0001-openai-wire-protocol_zh.md)) | **Adoption of OpenAI-Compatible Wire Protocol** | `Accepted` | 2026-10-22 | Adopt `POST /v1/chat/completions` as default wire protocol for zero-code drop-in client compatibility, instead of custom REST or pure gRPC. |
| [**0002**](0002-positioning-and-homelab-governance.md) ([中文](0002-positioning-and-homelab-governance_zh.md)) | **Product Positioning, Homelab LAN Sharing & Threat Model** | `Accepted` | 2026-10-22 | Keep EdgeCat a stateless governance gateway ("Gateway is the core, Hub is usage"), target Homelab/NAS LAN multi-device sharing with per-device cloud fallback quotas, and preserve ephemeral zero-disk PII vaulting. |
| [**0003**](0003-two-stage-request-mutator.md) ([中文](0003-two-stage-request-mutator_zh.md)) | **Two-Stage `RequestMutator` Inbound Extension Hook (R3.1)** | `Accepted` | 2026-11-19 | Define a zero-overhead, two-stage inbound hook (`StagePreMask` + `StagePostMask`) with monotonic `LocalOnly` enforcement, lossless `*Request` mutation helpers, and structured `*MutatorError` rejection. |
| [**0004**](0004-opt-in-layered-memory-plugin.md) ([中文](0004-opt-in-layered-memory-plugin_zh.md)) | **Opt-In Layered Memory Plugin, Governed Lifecycle & Prefix-Cache Two-Zone Injection (R3.2 / R3.2.1)** | `Accepted` | 2026-11-25 | Dual SQLite Writer/Reader pools, `tokenize='trigram'` CJK FTS5 search, two-zone Prefix-Cache friendly injection (`Zone 1` static `id ASC` rules + `Zone 2` pre-last-user dynamic context), atomic `SupersedeFact` chains (`<=5` hops), lock-free async hit tracking & dormancy sweeps, strict `client_name` isolation, and HMAC-SHA256 stable PII keys. |
