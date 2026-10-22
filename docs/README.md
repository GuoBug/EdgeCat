# EdgeCat Engineering Documentation

Welcome to the internal engineering documentation of EdgeCat. This repository follows standard platform engineering documentation practices.

## Directory Structure

```
docs/
├── README.md                                          # Documentation index (this file)
├── roadmap.md                                         # Product positioning & phased requirements backlog (EN)
├── roadmap_zh.md                                      # 项目需求池与演进路线图 (ZH)
└── adr/                                               # Architecture Decision Records (ADR)
    ├── README.md                                      # ADR registry and lifecycle index
    ├── 0001-openai-wire-protocol.md                   # ADR-0001: OpenAI Wire Protocol vs Custom/OpenAPI (EN)
    ├── 0001-openai-wire-protocol_zh.md                # ADR-0001: OpenAI Wire Protocol vs Custom/OpenAPI (ZH)
    ├── 0002-positioning-and-homelab-governance.md     # ADR-0002: Homelab LAN Sharing, Positioning & Threat Model (EN)
    └── 0002-positioning-and-homelab-governance_zh.md  # ADR-0002: 治理网关定位、家庭/内网共享与安全威胁模型 (ZH)
```

## Guidelines for Future Agents & Contributors

1. **Architecture Decisions**: When proposing structural changes (e.g., protocol rewrites, new storage engines, circuit-breaker algorithms), create a new ADR under `docs/adr/` numbered sequentially (`0002-...md`).
2. **README Discipline**: Keep `README.md` lean, punchy, and focused on quickstart and user onboarding. In-depth engineering rationale and trade-offs belong in `docs/adr/` or `docs/architecture/`.
