# EdgeCat Engineering Documentation

Welcome to the internal engineering documentation of EdgeCat. This repository follows standard platform engineering documentation practices.

## Directory Structure

```
docs/
├── README.md                          # Documentation index (this file)
└── adr/                               # Architecture Decision Records (ADR)
    ├── README.md                      # ADR registry and lifecycle index
    ├── 0001-openai-wire-protocol.md    # ADR-0001: OpenAI Wire Protocol vs Custom/OpenAPI (EN)
    └── 0001-openai-wire-protocol_zh.md # ADR-0001: OpenAI Wire Protocol vs Custom/OpenAPI (ZH)
```

## Guidelines for Future Agents & Contributors

1. **Architecture Decisions**: When proposing structural changes (e.g., protocol rewrites, new storage engines, circuit-breaker algorithms), create a new ADR under `docs/adr/` numbered sequentially (`0002-...md`).
2. **README Discipline**: Keep `README.md` lean, punchy, and focused on quickstart and user onboarding. In-depth engineering rationale and trade-offs belong in `docs/adr/` or `docs/architecture/`.
