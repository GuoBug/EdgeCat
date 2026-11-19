# ADR-0003: 双阶段入站扩展接口 `RequestMutator` 设计 (R3.1)

<p align="center">
  <a href="0003-two-stage-request-mutator.md">English</a> •
  <b>中文</b>
</p>

- **状态**: Accepted & Implemented (已通过并落地 `R3.1`)
- **日期**: 2026-11-19
- **决策人**: 郭强 (Guo Qiang)
- **涉及模块**: `internal/proxy/mutator.go`, `internal/proxy/protocol.go`, `internal/proxy/handler.go`

---

## 1. 背景与核心问题 (Context)

在 [ADR-0002](0002-positioning-and-homelab-governance_zh.md) 中，EdgeCat 确立了“网关是本体，中枢是用法”的架构原则，拒绝把长期记忆、自定义路由策略或业务规则硬编码进网关主循环。

然而在真实落地（以及后续 **R3.2 可选分层记忆插件示例**）中，开发者和内网管理员确实需要一种零侵入的扩展机制来实现：
1. 在请求发往上游模型前注入 System Prompt 或检索到的记忆事实；
2. 按客户端或自定义 Header 动态重写逻辑模型别名、调整推理参数；
3. 在占用本地并发槽位或消耗云端付费配额之前，执行自定义策略校验并返回标准 OpenAI 格式错误。

如果仅提供一个单阶段钩子，无论放在 PII 脱敏前还是脱敏后，都会带来明显缺陷：
- **仅放在脱敏后**：插件注入的文本（如检索出的记忆上下文）会直接绕过 PII 脱敏护栏，存在向云端泄露敏感信息的风险；
- **仅放在脱敏前**：插件无法感知 `PIIRedactedCount`，也无法基于脱敏结果执行路由收紧（例如强制 `LocalOnly` 或超过敏感词预算时拒绝放行）。

---

## 2. 决策：双阶段入站扩展管线 (`StagePreMask` + `StagePostMask`)

我们在 `internal/proxy/mutator.go` 中定义双阶段 `RequestMutator` 接口，按注册顺序依次运行在入站治理的两个关键边界上：

```
POST /v1/chat/completions
  │
  ▼
ParseRequest (无损 map[string]any + json.Number)
  │
  ▼
[Stage 1: StagePreMask]   ──► 注入上下文/记忆、重写逻辑模型、调整 PIIPolicy 或拦截
  │
  ▼
PII 策略评估与脱敏 (block / local_only / mask_on_egress / mask_always)
  │
  ▼
[Stage 2: StagePostMask]  ──► 观测 PIIRedactedCount、收紧 LocalOnly / QueueWaitMs 或拦截
  │
  ▼
并发准入与路由决策 (DecideRouteWithContext) 及本地/云端分发
```

### 核心契约
- **接口与适配器**：`RequestMutator` 定义 `Name() string`、`MutatePreMask(ctx, req, meta) error` 和 `MutatePostMask(ctx, req, meta) error`。只需单阶段的插件可直接使用 `PreMaskMutatorFunc`、`PostMaskMutatorFunc` 或 `MutatorFuncs` 零样板挂载。
- **挂载方式**：通过 `NewHandler(..., proxy.WithRequestMutators(...))` 或运行时 `handler.UseMutator(...)` 注册（内部由 `sync.RWMutex` 保护，自动忽略 `nil`）。
- **跨阶段状态传递**：`RequestMeta.Values`（`map[string]any`）提供请求级隔离暂存区，供插件在 `StagePreMask` 与 `StagePostMask` 之间共享状态，不污染发往上游的 JSON 负载。
- **无损请求操作原语**：`*Request` 新增 `SetLogicalModel`（同步更新用于云端降级映射的 `logicalModel` 和出站 `"model"` 字段）、`Get` / `Set` / `Delete`、`SetMessages`、`PrependSystemMessage` 与 `AppendMessage`，完整保留 `json.Number` 及厂商扩展字段。
- **结构化拦截**：返回 `*MutatorError` 可精确控制 HTTP 状态码与 OpenAI 错误信封；返回普通 `error` 默认转为 `400 Bad Request`（`code: "mutator_rejected"`）。所有拦截均以 `route_target = "blocked"` 写入异步 SQLite 审计日志。
- **运维可观测**：`GET /admin/status` 新增 `"mutators": [...]` 字段，按执行顺序展示当前挂载的插件名称。

---

## 3. 安全不变量 (Security Invariants)

1. **PreMask 注入内容必经 PII 护栏**：在 `StagePreMask` 中通过 `req.PrependSystemMessage` 等注入的任何文本，都会自动参与后续的 PII 策略评估与掩码，杜绝插件旁路泄露。
2. **`LocalOnly` 单调收紧**：一旦 PII `local_only` 策略将请求锁定为 `localOnly = true`，`StagePostMask` 仅允许收紧为 `true`，**严禁**降级回 `false`（`localOnly = localOnly || meta.LocalOnly`）。
3. **非法 `PIIPolicy` 故障安全回退**：若 `StagePreMask` 写入了未识别的 `PIIPolicy` 字符串，网关自动回退为最保守的 `"mask_always"`。
4. **默认零额外分配快路径**：未注册任何 `RequestMutator` 时，请求直接跳过 Header 克隆与 `RequestMeta` 分配，保持默认热路径零开销。

---

## 4. 使用示例

```go
handler := proxy.NewHandler(
    cfg, masker, r, guard, auditLogger, quotaMgr,
    proxy.WithRequestMutators(
        proxy.PreMaskMutatorFunc("system-context", func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
            if meta.ClientName == "workstation" {
                req.PrependSystemMessage("请用简洁的中文回答。")
            }
            return nil
        }),
        proxy.PostMaskMutatorFunc("pii-budget", func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
            if meta.PIIRedactedCount > 5 {
                return &proxy.MutatorError{
                    StatusCode: http.StatusForbidden,
                    Type:       "policy_error",
                    Code:       "pii_budget_exceeded",
                    Message:    "单次请求包含过多敏感实体，已被本地策略拦截",
                }
            }
            return nil
        }),
    ),
)
```

---

## 5. 影响评估、代价与边界 (Consequences & Trade-Offs)

### 积极影响
- 在不破坏 `CGO_ENABLED=0` 纯静态编译与无损协议透传的前提下，为 **R3.2（可选分层记忆插件）** 及自定义内网治理策略提供了边界清晰、可单测的扩展接缝。

### 代价与边界说明
- **同步热路径延迟预算**：`RequestMutator` 在路由前同步执行，插件内部耗时将直接计入首字延迟（TTFT）；涉及外部查询或 SQLite 检索的插件（如 R3.2）必须基于 `ctx` 严格控制超时并使用独立读连接池。
- **仅限入站阶段**：为保证流式 SSE 滑动窗口 PII 还原的确定性与低首字延迟，`RequestMutator` 明确不介入出站 SSE 分片改写。
- **编译期接口扩展**：延续 EdgeCat 的 Non-Goals 边界，扩展点采用 Go 编译期接口，不引入动态脚本解释器或热路径内联 Shell/MCP 执行。
