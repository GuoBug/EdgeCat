# EdgeCat: 本地优先 (Local-First) AI 推理治理网关

<p align="center">
  <a href="README.md">English</a> •
  <b>中文</b>
</p>

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![CGO_ENABLED](https://img.shields.io/badge/CGO_ENABLED-0-success?style=flat)]()
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-Local--First_Dual--Track-orange)]()

> **EdgeCat** 是一个轻量级、确定性、本地优先的 AI 推理治理网关，使用 Go 1.22+ 编写并实现 `CGO_ENABLED=0` 纯静态编译。  
> 专为解决边缘/本地模型（如 Ollama、vLLM、llama.cpp）与云端保底端点之间的流式治理、敏感信息过滤、冷启动超时熔断及审计入库而构建。

---

## 核心痛点与工程解法

在传统的 AI 应用架构中，将请求直接打到本地推理端点往往面临四大工程痛点：
1. **GPU 负载与假死难以从 OS 内存判断**：本地模型排队卡死时，下游客户端无限挂起；
2. **跨 Chunk 的 PII 还原丢失**：流式 SSE 返回时，占位符被 Token 切片拆分（例如 `{{EC_PII_` 与 `PHONE_1}}` 落在不同数据包），常规正则还原直接失效；
3. **输出格式失控**：模型常常无视 `response_format` 强行包裹 ````json 代码块，破坏下游反序列化契约；
4. **同步写日志拖慢推理延迟**：传统网关在 HTTP 协程中同步写入数据库，导致首字耗时（TTFT）劣化。

**EdgeCat 通过以下五大确定性机制彻底化解上述痛点：**

```
                       ┌──────────────────────────────────────────────┐
                       │          Client (OpenAI SDK / HTTP)          │
                       └──────────────────────┬───────────────────────┘
                                              │ POST /v1/chat/completions
                                              ▼
                        ┌────────────────────────────────────────────┐
                        │  PII Filter: Regex Masker & Memory Vault   │
                        │  (Phone / Email / IPv4 / APIKey Masking)   │
                        └─────────────────────┬──────────────────────┘
                                              ▼
                        ┌────────────────────────────────────────────┐
                        │        Tier Router & Model Aliasing        │
                        └───────┬────────────────────────────┬───────┘
          Local Semaphore Free  │                            │ Local Saturated /
           & TTFT < 3500ms      │                            │ TTFT Exceeded / Refused
                                ▼                            ▼
            ┌───────────────────────┐            ┌───────────────────────┐
            │   Local Tier (Ollama) │            │   Cloud Tier (OpenAI) │
            │   e.g. qwen2.5:7b     │            │   e.g. gpt-4o-mini    │
            └───────────┬───────────┘            └───────────┬───────────┘
                        │                                    │
                        └─────────────────┬──────────────────┘
                                          │ Raw Response / SSE Stream
                                          ▼
                      ┌───────────────────────────────────────────────┐
                      │ Sliding-Window SSE Rehydrator & JSON Guard    │
                      │ (Chunk Stitching + Code Fences Stripping)     │
                      └───────────────────┬───────────────────────────┘
                                          │
                                          ├─► Flush to Client (http.Flusher)
                                          │
                                          ▼ (Non-blocking Bounded Chan)
                      ┌───────────────────────────────────────────────┐
                      │    Async SQLite Logger (modernc.org/sqlite)   │
                      │    WAL + NORMAL PRAGMA (Batch Worker)         │
                      └───────────────────────────────────────────────┘
```

---

## 五大核心架构支柱

### 1. 滑动窗口流式还原 (Sliding-Window SSE Rehydration)
- **掩码阶段**：请求进入时，提取手机号、邮箱、内网 IPv4 及各类 API Key，替换为确定性占位符 `{{EC_PII_<TYPE>_<INDEX>}}`（同值去重，保持上下文一致性），原值隔离保存在当前 Context 的 `Vault` 中。
- **流式拼接**：设计了双游标轻量级滑动窗口缓冲器。当检测到未闭合的占位符前缀（如 `{{EC_` 或 `{{EC_PII_`）时，网关将截断部分暂存至 `pending` 缓冲区，前序安全内容即刻刷出；下一 Chunk 到达拼接闭合后，完成替换再向下游 `http.Flusher` 输出，完美解决 Token 分词跨 Chunk 截断痛点。

### 2. 并发信号量与 TTFT 首字超时降级 (Circuit Breaker & Fallback)
- 不依赖模糊的操作系统 GPU/内存指标，采用带权通道信号量管理本地最大并发数（`max_concurrent_local`）。
- 建立独立的 **TTFT（Time-To-First-Token）首字看门狗**：在向本地发起请求时启动计时器。若本地并发满载、网络拒连或超出 `ttft_timeout_ms` 未吐出首个有效 Byte/Chunk，网关在向客户端输出任何内容前立即触发静默熔断，无缝重写请求转交云端保底端点（Cloud Tier）。

### 3. 模型别名动态重写 (Model Aliasing)
- 客户端无需感知底层模型差异，统一请求 `default` 或 `gpt-4o-mini`。
- 路由至 Local Tier 时自动重写为配置的本地模型名（如 `qwen2.5:7b`），降级至 Cloud Tier 时重写为云端模型名，并正确重新计算 HTTP `Content-Length` 与路由标头。

### 4. 契约校验与单次自修复闭环 (Strict JSON Guard & Repair Loop)
- 当请求包含 `response_format: {"type": "json_object"}` 或标头 `X-EdgeCat-Strict-JSON: true` 时，自动剥离输出中多余的 ````json / ```` Markdown 代码块标签与空白注释。
- 若提取后校验仍不合法，受控触发最多 1 次单轮 Prompt 修复调用（带超时限制），杜绝递归死循环。

### 5. 无锁异步 SQLite 批量审计 (Async Batch SQLite Logger)
- 引入纯 Go 编写的 `modernc.org/sqlite`，连接初始化时显式开启 `_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)`。
- HTTP 协程仅需向有界 Channel（默认 10,000 容量）发送审计条目，耗时趋近于 0，写满时自动丢弃保护低延迟；后台唯一 Worker 协程按批量阈值（如 50 条）或定时器聚合单事务落库。

---

## 快速上手

### 1. 编译
本项目完全支持 `CGO_ENABLED=0` 纯静态编译：
```bash
# 生成纯静态无依赖可执行文件
make build
# 或直接执行：
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/edgecat ./cmd/edgecat
```

### 2. 运行单元测试
```bash
make test
# 或执行：
go test -v ./...
```

### 3. 配置与启动
参考 `configs/edgecat.example.yaml` 编写配置文件：
```yaml
server:
  host: "0.0.0.0"
  port: 8080

local:
  endpoint: "http://127.0.0.1:11434/v1"
  max_concurrent_local: 2
  ttft_timeout_ms: 3500
  model_mapping:
    "default": "qwen2.5:7b"
    "gpt-4o-mini": "qwen2.5:7b"

cloud:
  endpoint: "https://api.openai.com/v1"
  api_key: "sk-your-cloud-api-key"
  timeout_ms: 60000
  model_mapping:
    "default": "gpt-4o-mini"
    "qwen2.5:7b": "gpt-4o-mini"

filter:
  enabled: true
  mask_phone: true
  mask_email: true
  mask_ipv4: true
  mask_apikey: true

contract:
  strict_json_enabled: true
  max_repair_attempts: 1

audit:
  sqlite_path: "data/edgecat_audit.db"
  batch_size: 50
  flush_interval_ms: 1000
```

启动网关：
```bash
./bin/edgecat -config configs/edgecat.example.yaml
```

---

## 接口说明与生态接入 (Endpoints & Compatibility)

EdgeCat 100% 兼容 **OpenAI ChatCompletion 协议**（支持零改造即插即用）：
- **`POST /v1/chat/completions`**：支持标准非流式 JSON 及实时 SSE 流式（`stream: true`）传输。
- **`GET /health`**：实时返回本地/云端端点状态、本地活动信号量并发数、累计降级次数以及异步审计日志吞吐指标。
- **`GET /v1/models`**：提供 OpenAI 兼容的模型列表发现。

> 💡 **架构决策沉淀**：关于为什么全面采用 OpenAI 兼容协议而非私有 REST、以及其与 OpenAPI 的概念辨析，详见架构决策记录 [ADR-0001: 采用 OpenAI 兼容协议作为核心通信协议](docs/adr/0001-openai-wire-protocol_zh.md)。

### 客户端零侵入接入示例：
- **桌面与 Web 客户端 (Chatbox / Cherry Studio / NextChat)**：
  - API 格式：选择 `OpenAI API`
  - API 地址 (Base URL)：`http://localhost:8080/v1`
  - API Key：任意填写（如 `none`）
- **Python (官方 `openai` SDK)**：
  ```python
  from openai import OpenAI

  # 直接将基地址指向 EdgeCat，无需改动任何业务逻辑
  client = OpenAI(base_url="http://localhost:8080/v1", api_key="none")

  response = client.chat.completions.create(
      model="gpt-4o-mini",  # 逻辑模型名，EdgeCat 自动根据策略重写
      messages=[{"role": "user", "content": "我的电话是 13800138000"}],
      stream=True,
  )
  for chunk in response:
      if chunk.choices[0].delta.content:
          print(chunk.choices[0].delta.content, end="", flush=True)
  ```

---

## 人机协同与演进理念 (Collaboration Note)

本项目由作者 **Guo Qiang** 借助 AI Pair Programming（人机结对共创）通过“干中学（Learning by Doing）”模式探索落地：
- **人提的关键点**：来源于真实生产场景中本地大模型“首字卡死无限等待”、“单机 GPU 显存过载崩溃”以及“私有数据流式送模泄露”等系统痛点；
- **AI 提的关键点**：聚焦于“滑动窗口双游标状态机”、“SSE 跨分包占位符拆分防丢”、“HTTP 流式劫持与未刷 Header 前静默降级”及“WAL 模式下 SQLite 单协程批量写入无锁优化”。

欢迎对 AI 边缘网关、确定性工作流以及系统工程感兴趣的同行与架构师交流指教！

---

> **关于作者**  
> **郭强 (GuoBug)**，Product Engineer，做平台工程也做业务增长。目前主要在折腾 AI 工作流编排、DAG 状态机与确定性系统架构。  
> 开源项目与主页：[https://github.com/GuoBug](https://github.com/GuoBug) · [https://guobug.github.io](https://guobug.github.io)  
> 欢迎就工作流引擎架构、拓扑调度和低门槛开发体验交流指教。
