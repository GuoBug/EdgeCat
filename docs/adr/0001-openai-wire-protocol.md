# ADR-0001: Adoption of OpenAI-Compatible Wire Protocol

<p align="center">
  <b>English</b> •
  <a href="0001-openai-wire-protocol_zh.md">中文</a>
</p>

- **Status**: Accepted
- **Date**: 2026-10-22
- **Author**: Guo Qiang
- **Context Area**: Gateway Ingress / Egress Protocols

---

## 1. Context and Problem Statement

When designing the EdgeCat governance gateway, a fundamental architectural question arose:
> *Should EdgeCat introduce a custom bespoke REST/gRPC API, or conform strictly to an existing industry wire protocol?*

Furthermore, during developer discussions, a frequent confusion occurred between:
1. **OpenAI-Compatible Wire Protocol** (the conversational HTTP/SSE API standard).
2. **OpenAPI Specification** (the OAS/Swagger schema definition standard).

EdgeCat requires an ingress and egress interface that allows seamless interception of AI traffic without forcing developers or client applications to rewrite code.

---

## 2. Conceptual Disambiguation

| Concept | Nature | Function in AI Ecosystem |
| :--- | :--- | :--- |
| **OpenAI-Compatible API**<br>*(Adopted by EdgeCat)* | **Wire Protocol Standard** | Specifies HTTP endpoints (`POST /v1/chat/completions`), JSON message structure (`role`, `content`), and Server-Sent Events (SSE) streaming tokens (`data: {"choices":[{"delta":...}]}`). It is the **universal "Type-C interface"** of Generative AI. |
| **OpenAPI Specification (OAS)**<br>*(Formerly Swagger)* | **Documentation / Schema Meta-Format** | A YAML/JSON specification format used to describe and document generic RESTful APIs. It defines how to write API specs, but does not prescribe AI conversation semantics. |

---

## 3. Decision Drivers

1. **Zero-Code Drop-In Adoption**: Millions of existing applications, Agent frameworks (LangChain, LlamaIndex, Dify), desktop clients (Chatbox, Cherry Studio, NextChat), and official SDKs (`import openai`) must connect to EdgeCat simply by altering their `Base URL` to `http://localhost:8080/v1`.
2. **Dual-Tier Interoperability**: Both local runtimes (Ollama, vLLM, llama.cpp, LocalAI) and cloud providers (DeepSeek, Qwen/DashScope, Moonshot/Kimi, Zhipu GLM, OpenAI) natively expose this wire protocol. EdgeCat can act as a transparent proxy middlebox between any compatible client and any compatible inference tier.
3. **Deterministic Governance Enforcement**: Transparently injecting PII redaction, concurrency circuit breaking, and SQLite auditing requires the gateway to speak the identical protocol as the upstream client and downstream model.

---

## 4. Considered Alternatives

### Alternative A: Custom Bespoke REST API (e.g., `POST /api/v1/govern/inference`)
- **Pros**: Complete freedom over parameter naming and internal feature flags.
- **Cons**: Severe integration friction. Every client, SDK, and UI would need a custom driver or wrapper to talk to EdgeCat, destroying developer adoption.
- **Verdict**: Rejected.

### Alternative B: Pure gRPC API
- **Pros**: High binary throughput and strict schema definition.
- **Cons**: Poor web/browser compatibility; modern LLM developer tooling is overwhelmingly HTTP/SSE-centric.
- **Verdict**: Rejected as primary gateway interface (may be considered as an internal IPC optimization in future phases).

### Alternative C: OpenAI-Compatible Wire Protocol (`POST /v1/chat/completions`)
- **Pros**: Zero-code drop-in compatibility across the entire global AI ecosystem.
- **Cons**: EdgeCat must handle token chunk fragmentation when streaming SSE responses (e.g., placeholders split across chunks).
- **Verdict**: **Accepted**.

---

## 5. Decision Outcome

**EdgeCat strictly adopts the OpenAI-Compatible Wire Protocol** for all inference proxy operations:
1. **Primary Endpoints**:
   - `POST /v1/chat/completions` (JSON & SSE streaming)
   - `GET /health` (Gateway metrics & tier status)
   - `GET /v1/models` (Catalog discovery)
2. **Engineering Solution for SSE Fragmentation**:
   - Implemented the **Sliding-Window SSE Rehydrator** (`internal/filter/pii.go`) to buffer and stitch split placeholder tokens across streaming chunk boundaries without dropping or corrupting data.

---

## 6. Consequences

### Positive:
- **Instant Client Compatibility**: Any tool supporting custom OpenAI endpoints (e.g., Chatbox, Cherry Studio, Python `openai` library) works out-of-the-box.
- **Symmetric Routing**: EdgeCat can route requests to local Ollama or cloud DeepSeek without protocol translation.
- **Developer Experience**: Eliminates learning curve for developers already familiar with standard AI SDKs.

### Negative / Mitigations:
- **Streaming Parser Complexity**: Gateway must maintain lightweight sliding-window buffers for SSE streams.  
  *Mitigation*: Solved via deterministic sliding-window state machine with bounded memory overhead.
