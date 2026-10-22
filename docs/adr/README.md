# Architecture Decision Records (ADR)

This directory documents the critical architectural and engineering decisions made during the evolution of EdgeCat. Each record outlines the context, rationale, trade-offs, and consequences of a significant architectural choice.

For future agents and contributors, review these records before proposing structural or protocol changes.

## Index of Architecture Decision Records

| ADR | Title | Status | Date | Decision Summary |
| :--- | :--- | :--- | :--- | :--- |
| [**0001**](0001-openai-wire-protocol.md) | **Adoption of OpenAI-Compatible Wire Protocol** | `Accepted` | 2026-10-22 | Adopt `POST /v1/chat/completions` as default wire protocol for zero-code drop-in client compatibility, instead of custom REST or pure gRPC. |
