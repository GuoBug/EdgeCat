# EdgeCat 项目需求池与演进路线图 (Requirements & Evolution Roadmap)

<p align="center">
  <a href="roadmap.md">English</a> •
  <b>中文</b>
</p>

本文档记录 **EdgeCat** 的核心架构定位、已完成里程碑、待落地需求池（Backlog）以及明确排除的非目标边界（Non-Goals）。所有功能演进均围绕 **“本地优先的确定性流式治理网关（兼家庭/小团队内网共享与 PatchCat 安全伴侣）”** 展开。

---

## 一、 核心定位与场景边界

1. **单机极客守护进程（Localhost Sidecar）**：跑在个人工作站（`127.0.0.1:8080`），接管本机 IDE 插件、CLI 工具与 **PatchCat** 编排器，实现本地 Ollama 优先、云端保底、流式隐私脱敏。
2. **家庭 / 小团队内网共享网关（Homelab / Studio LAN Gateway）**：常驻在家庭 NAS、Mac mini 或软路由上，供家庭成员或 2~3 人小团队的多台设备共用：
   - **统一托管云端主 API Key**（客户端仅持子令牌，无需到处粘贴真实 Key）；
   - **统一隐私脱敏护栏**（任何内网设备发出的手机号、邮箱、内网 IP、密钥在进公网云端前强制替换为占位符，流式返回时无感还原）；
   - **本地免费算力共享 + 云端降级配额熔断**（白嫖本地显卡不限流，触发付费云端降级时按设备子令牌执行每日限额，防止死循环或 XSS 刷爆账单）；
   - **统一分账审计**（按设备/成员统计本地调用次数、云端降级次数与延迟指标）。

---

## 二、 演进里程碑与需求池 (Phased Backlog)

### ✅ Phase 1 & 1.5：确定性流式治理与无损协议底座（已完成）

| 编号 | 需求模块 | 核心工程实现与验收标准 | 状态 |
| :--- | :--- | :--- | :---: |
| **R1.1** | **滑动窗口 SSE 流式脱敏与还原** | 入站正则掩码（手机号/邮箱/内网 IPv4/API Key）存入请求级内存 `Vault`；出站通过双游标缓冲器拼合跨 Chunk 截断的 `{{EC_PII_...}}` 占位符。 | ✅ 已完成 |
| **R1.2** | **并发信号量与未发 Header 前静默降级** | 带权通道信号量控制本地并发（`max_concurrent_local`）+ 独立 TTFT 首字看门狗，超时或饱和时在向客户端写 Header 前静默切流至云端。 | ✅ 已完成 |
| **R1.3** | **无损协议透传层 (`internal/proxy/protocol.go`)** | 废除有损结构体重建；入站采用 `map[string]any` + `json.Number` 原样保留 `tools`、`tool_choice`、`top_p`、`seed` 等全部扩展字段，同时保持原始逻辑模型名不可变以确保降级路由映射准确；出站在原始字节上直接还原占位符，100% 保留 `tool_calls` 与 `reasoning_content`。 | ✅ 已完成 |
| **R1.4** | **多模态与工具参数深度脱敏** | 支持 `messages[].content` 为字符串或多模态数组（仅脱敏 `type=="text"` 分块，图片/音频原样透传）；同步对 `tool_calls[].function.arguments` 执行脱敏。 | ✅ 已完成 |
| **R1.5** | **SSE 滚动空闲写超时 (`stream_idle_timeout_ms`)** | 使用 `http.ResponseController.SetWriteDeadline` 在每次 `Flush` 前刷新滚动空闲截止时间（默认 300s），解决固定 `WriteTimeout` 腰斩本地慢速模型长输出的问题。 | ✅ 已完成 |
| **R1.6** | **非流式契约护栏 (`strict_json_enabled`)** | `contract.strict_json_enabled` 作为真实总开关；开启且请求要求 JSON 时，自动剥离 Markdown 代码围栏并触发最多 1 次带超时自修复。 | ✅ 已完成 |
| **R1.7** | **无锁异步 SQLite 批量审计** | 基于 `modernc.org/sqlite`（`CGO_ENABLED=0`）+ WAL 模式，单写协程按批量或定时器异步刷盘，满队列非阻塞丢弃保低延迟。 | ✅ 已完成 |

---

### 🚧 Phase 2：家庭 / 小团队内网共享与 PatchCat 安全伴侣（下一步核心）

> **目标**：无需引入重型 UI 或多租户计费系统，仅用轻量配置与 SQLite 即可安全支撑“一台 NAS、多台设备/多人共用”与浏览器端 PatchCat 跨域直连。

| 编号 | 需求名称 | 详细工程规约 | 优先级 |
| :--- | :--- | :--- | :---: |
| **R2.1** | **默认安全与 Fail-Closed 局域网启动门卫** | 1. 默认 `server.host` 收紧为 `"127.0.0.1"`。<br>2. **启动强制自检**：当 `server.host` 配置为非回环地址（如 `"0.0.0.0"` 或局域网 IP）且 `auth.enabled` 未开启（或未配置任何有效客户端 Token）时，启动直接报错退出（除非显式设置 `allow_insecure_lan: true`），杜绝内网无鉴权裸奔。 | **P0** |
| **R2.2** | **多设备子令牌鉴权 (`auth.clients`)** | 1. 支持在 `edgecat.yaml` 中配置多个客户端条目：`name`（如 `guo-mac`、`family-ipad`、`patchcat-web`）、`token`（`Bearer ec-...`）。<br>2. 校验入站 `Authorization: Bearer <token>`，使用 `subtle.ConstantTimeCompare` 防止时序侧信道；未授权返回 `401 Unauthorized`。<br>3. `/health` 可保持免鉴权只读探活（不暴露敏感配置）。 | **P0** |
| **R2.3** | **双轨配额控制：本地无限白嫖，云端每日限额 (`daily_cloud_limit`)** | 1. 每个客户端 Token 可配置 `daily_cloud_limit`（每日允许触发云端付费调用的最大次数，`0` 表示不限制，`-1` 表示禁止走云端仅允许走本地）。<br>2. **核心机制**：请求路由至免费 **Local Tier** 时完全不扣减配额；仅当路由或降级至付费 **Cloud Tier** 时，检查并原子递增该客户端当日云端计数（按 UTC/本地自然日自动重置）。<br>3. 超出云端配额时，拒绝发往云端并返回 `429 Too Many Requests`（`{"error": "daily cloud fallback quota exceeded for client"}`）。 | **P0** |
| **R2.4** | **受控 CORS 与 Chrome PNA 局域网预检** | 1. 配置项 `server.allowed_origins`（支持精确域名白名单，如 `https://patchcat.dev`、`http://localhost:5173`，严禁在启用鉴权时无脑反射任意 `*`）。<br>2. 完整处理 `OPTIONS` 预检请求（返回 `204 No Content`）。<br>3. 支持 Chrome Private Network Access 规范：当收到 `Access-Control-Request-Private-Network: true` 时，响应头注入 `Access-Control-Allow-Private-Network: true`，确保公网 HTTPS 部署的 PatchCat 前端可安全访问用户本机或局域网 NAS 上的 EdgeCat。 | **P1** |
| **R2.5** | **按设备/成员维度的 SQLite 分账审计** | 1. `audit_logs` 表新增 `client_name TEXT NOT NULL DEFAULT 'anonymous'` 列（支持已有数据库启动时自动 `ALTER TABLE` 幂等迁移）。<br>2. 在 `/health` 端点中增加 `clients_usage` 汇总视图，实时展示各设备的今日请求数與剩余云端降级配额。 | **P1** |

#### Phase 2 实施前待定的设计约束 (Design Constraints to Resolve First)

> 以下 5 条由 **DeepSeek 交叉审阅**（2026-10-22）提出，尚未并入上表验收标准。开工前需先逐条定论，否则会在实现阶段返工。

| # | 待定问题 | 建议结论 | 影响需求 |
| :--- | :--- | :--- | :--- |
| **D1** | **配额判定时机**：流式请求的降级发生在 `tryLocalStream` 失败之后、SSE Header 写出之前。若配额在 Header 之后才判定，`429` 已经无法回传 | 配额检查必须插在「本地失败 → 调用云端」之间且早于 `WriteHeader`，这是唯一的拒绝窗口 | R2.3 |
| **D2** | **配额计数持久化**：纯内存原子计数在进程重启后归零，而 NAS 会重启，等于当日配额可被重启绕过 | 每日计数落 SQLite（每客户端每日一行），启动时加载；内存仅作热路径缓存 | R2.3 / R2.5 |
| **D3** | **`daily_cloud_limit: -1` 的失败语义**：本地不可用且该客户端被禁止走云端时，应返回什么 | 返回 `503 Service Unavailable` 并给出明确文案（本地不可用且该客户端禁止云端降级），而非笼统的 `429` | R2.3 |
| **D4** | **配额自然日时区**：按 UTC 还是服务端本地时区重置 | 采用服务端本地时区（家庭场景用户预期为本地日），并在 `/health` 暴露下次重置时间点 | R2.3 |
| **D5** | **`/v1/models` 仍为硬编码**：当前固定返回三个模型名，多设备共享时客户端（Cherry Studio 等）无法发现配置中的逻辑模型，物理模型名反而被暴露 | 改为从 `local.model_mapping` / `cloud.model_mapping` 的键派生逻辑模型列表，物理名不出现在发现接口 | R2.4 前置（客户端可用性） |

---

### 🔭 Phase 3：可插拔扩展契约与长期验证（远期储备）

| 编号 | 需求名称 | 详细工程规约 | 优先级 |
| :--- | :--- | :--- | :---: |
| **R3.1** | **双阶段扩展接口 (`RequestMutator`)** | 在 `internal/proxy` 中提炼干净的入站请求变异器接口（在 PII 掩码前执行），方便后续以零侵入插件形式挂载自定义策略。 | **P2** |
| **R3.2** | **可选的分层记忆插件示例 (Opt-in Memory Plugin)** | 仅作为 `RequestMutator` 的插件示例（默认关闭）：<br>1. **读写双句柄**：分离 SQLite Writer（`MaxOpenConns(1)`）与 Reader 连接池，防止热路径读取被批量审计写入阻塞。<br>2. **中文 FTS5 支持**：显式使用 `tokenize='trigram'`。<br>3. **分层存储与稳定键**：长期记忆仅存本地模型蒸馏后的非敏感事实（Facts）；若需跨请求关联 PII，将自增序号升级为 `HMAC-SHA256(原文, 本地密钥)` 前 8 字节稳定键，并在开启的多用户场景下强制按 `client_name` 隔离命名空间。 | **P3** |
| **R3.3** | **90 天真实生产运行基准报告** | 在个人工作站与家庭 NAS 上连续运行 EdgeCat + PatchCat，采集真实生产指标（本地 7B 承接率、TTFT 超时降级率、节省的云端 Token 成本、PII 拦截次数），沉淀技术复盘长文。 | **P2** |

---

## 三、 明确不做清单 (Explicit Non-Goals)

为了保持 EdgeCat 的极简、确定性与系统工程纯度，以下方向**明确排除在项目范围之外**：
1. ❌ **不做破坏 `CGO_ENABLED=0` 的重型依赖**：不引入依赖 CGO 的 `mattn/go-sqlite3`、SQLCipher 或外部 C++ 分词库，坚守纯静态单二进制交付。
2. ❌ **不做公网多租户计费与用户管理后台**：不做充值、计费账单、租户注册 UI；团队间分享工作流统一通过导出/导入 **PatchCat DAG JSON** 完成。
3. ❌ **不在网关热路径内联执行 MCP / 本地 Shell 工具**：网关不直接拦截 `tool_calls` 并在网关进程内跑脚本（避免流式状态机复杂化与远程代码执行 RCE 风险），只负责对工具定义与参数做 100% 无损透传与 PII 脱敏。
