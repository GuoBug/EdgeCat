# ADR-0001: 采用 OpenAI 兼容协议作为网关核心通信协议

<p align="center">
  <a href="0001-openai-wire-protocol.md">English</a> •
  <b>中文</b>
</p>

- **状态**: Accepted (已通过)
- **日期**: 2026-10-22
- **决策人**: 郭强 (Guo Qiang)
- **涉及模块**: 网关出入站通信协议 (Ingress / Egress Protocols)

---

## 1. 背景与问题定义 (Context)

在构建 EdgeCat 推理治理网关的初始架构时，面临一个核心协议决策：
> *网关应该自行定义一套专有的 REST/gRPC 接口，还是坚决对齐现有的行业标准通信协议？*

同时在技术沟通中，常常遇到以下两个概念的认知混淆：
1. **OpenAI 兼容协议（OpenAI-Compatible Wire Protocol）**：面向大模型对话与流式输出的 HTTP/SSE 协议标准。
2. **OpenAPI 规范（OpenAPI Specification，前身 Swagger）**：用于描述通用 RESTful API 的文档元数据格式。

EdgeCat 需要一套能让任何现有客户端与业务系统**零改造直接接入**的通用通信契约。

---

## 2. 概念辨析 (Disambiguation)

| 核心概念 | 本质定义 | 在 AI 生态中的作用 |
| :--- | :--- | :--- |
| **OpenAI 兼容协议**<br>*(EdgeCat 所采用)* | **线缆级网络通信协议** | 规定了具体路径（`POST /v1/chat/completions`）、JSON 请求体结构（`model`、`messages`、`role`、`content`）以及 Server-Sent Events (SSE) 逐字流式打字机格式。它相当于大模型领域的 **Type-C 工业接口**。 |
| **OpenAPI 规范**<br>*(前身 Swagger)* | **接口文档与元数据标准** | 规定如何用 YAML/JSON 书写一份 API 说明书，属于描述接口格式的排版规范，并不规定大模型交互的业务语义。 |

---

## 3. 决策驱动因素 (Decision Drivers)

1. **零改造、即插即用（Zero-Code Drop-In Adoption）**：全球数以百万计的 AI 应用、Agent 框架（LangChain、LlamaIndex、Dify）、客户端工具（Chatbox、Cherry Studio、NextChat、沉浸式翻译）以及官方 SDK（`openai` 库），只需把 `Base URL` 改为 `http://localhost:8080/v1`，即可直接接入。
2. **双轨端点天然对齐（Dual-Tier Interoperability）**：无论是本地推理引擎（Ollama、vLLM、llama.cpp），还是各大云端模型服务商（DeepSeek、通义千问、Kimi、智谱、OpenAI），全都原生开放该接口。EdgeCat 作为透明代理中间件，上下游协议完全对称。
3. **确定性隐式治理（Deterministic Governance）**：只有协议一致，网关才能在客户端与模型之间隐形完成 PII 脱敏、TTFT 熔断降级与异步 SQLite 审计，业务层完全无感知。

---

## 4. 备选方案权衡 (Considered Alternatives)

### 备选 A：自定义私有 REST 协议 (如 `POST /api/v1/govern/inference`)
- **收益**：自由定义参数字段，不受外部模型协议约束。
- **代价**：集成阻力极大。任何第三方客户端或 SDK 都无法直连，用户必须为了网关单独写适配层，严重破坏易用性。
- **结论**：**否决 (Rejected)**。

### 备选 B：纯 gRPC 协议
- **收益**：二进制高性能、强类型约束。
- **代价**：Web 前端与轻量级 Python 调试极不友好；目前大模型生态事实标准是 HTTP/SSE。
- **结论**：**现阶段否决 (Rejected)**（未来仅保留作为内部微服务 IPC 优化选项）。

### 备选 C：完全对齐 OpenAI 兼容协议 (`POST /v1/chat/completions`)
- **收益**：生态直连、零开发适配、极速推广。
- **代价**：网关必须负责解决流式 SSE 返回时 Token 切片把占位符打断（跨 Chunk 截断）的复杂性。
- **结论**：**通过 (Accepted)**。

---

## 5. 最终决策与工程落地 (Decision Outcome)

**EdgeCat 正式确立 OpenAI-Compatible Wire Protocol 作为全系统标准接口：**
1. **暴露端点**：
   - `POST /v1/chat/completions`（支持标准 JSON 与实时 SSE 流式 `stream: true`）
   - `GET /health`（实时监控指标与端点健康）
   - `GET /v1/models`（模型列表服务发现）
2. **代价的工程解法**：
   - 在 [`internal/filter/pii.go`](file:///f:/git/EdgeCat/internal/filter/pii.go) 中设计并实现了**双游标滑动窗口流式缓冲器（Sliding-Window SSE Rehydrator）**，当占位符在 Chunk 边缘被割裂时自动挂起暂存，后续拼合后再向下游刷出，彻底攻克流式截断痛点。

---

## 6. 决策影响评估 (Consequences)

### 积极影响：
- 任何兼容 OpenAI 的现有工具（Chatbox、Cherry Studio、Python 代码）**无需改写一行逻辑即可直接使用**。
- 网关具备高度通用性，无论底层接入本地 Ollama 还是云端 DeepSeek，路由逻辑对齐统一。

### 代价与对策：
- 网关需要维护轻量级流式解析缓冲逻辑；已由纯 Go 实现的低开销滑动窗口状态机解决，单请求额外内存分配接近于零。
