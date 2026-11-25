# ADR-0004: 可选分层记忆插件、受治理生命周期与双区 Prefix-Cache 注入设计 (R3.2 / R3.2.1)

<p align="center">
  <a href="0004-opt-in-layered-memory-plugin.md">English</a> •
  <b>中文</b>
</p>

- **状态**: Accepted & Implemented (已通过并落地 `R3.2`，于 `R3.2.1` 演进升级)
- **日期**: 2026-11-20（`R3.2.1` 更新：2026-11-25）
- **决策人**: 郭强 (Guo Qiang)
- **涉及模块**: `internal/memory/plugin.go`, `internal/proxy/protocol.go`, `internal/filter/pii.go`, `internal/config/config.go`, `internal/proxy/handler.go`, `cmd/edgecat/main.go`

---

## 1. 背景与核心问题 (Context)

在 [ADR-0002](0002-positioning-and-homelab-governance_zh.md) 中，EdgeCat 为任何有状态的记忆能力划定了两条硬红线：
1. **绝不破坏 `CGO_ENABLED=0`**：不引入 C++ 中文分词库、`mattn/go-sqlite3` 或 SQLCipher；
2. **绝不落盘明文 PII**：记忆能力必须默认关闭（Opt-in），在家庭/内网多端共享场景下强制按客户端隔离命名空间，并且只能以 [ADR-0003](0003-two-stage-request-mutator_zh.md) 定义的 `RequestMutator` 插件形态挂载，绝不侵入网关主循环。

**R3.2** 落地了双连接池 SQLite FTS5 分层记忆插件（`internal/memory`）与跨请求 HMAC 稳定 PII 键（`filter.NewStableVault`）。在此基础上，**R3.2.1** 参考 Mirabase 的受治理记忆模型，在不放松任何架构红线的前提下解决三个实际工程问题：
1. **多轮对话 Prefix Cache 击穿**：每轮随提问变化的动态检索结果若直接插入 `messages[0]`，会导致后续整段历史消息与工具定义的 KV Cache 前缀全部失效；
2. **事实演进与重复堆积**：长期运行中配置或偏好发生变更时，缺乏原子替代链与写入幂等去重会导致新旧矛盾事实并存；
3. **冷记忆噪音与命中统计读写冲突**：需要追踪事实命中频次并休眠长期未用或引文失效的条目，但严禁在 `MutatePreMask` 热路径做同步写库。

---

## 2. 架构决策

### 2.1 SQLite 读写双句柄分离与 Schema 幂等演进
如果让热路径 `StagePreMask` 检索与后台写入共享同一个 `MaxOpenConns(1)` 连接，所有并发推理请求都会在写事务后排队。
- **双连接池物理隔离**：
  - `writerDB`：`journal_mode(WAL)`、`synchronous(NORMAL)`、`MaxOpenConns(1)` —— 串行承接 `AddFact`、`SupersedeFact`、`SweepDormantUnused`、`MarkQuoteMissing`、`WakeFact`、`AddShortTerm`、`PurgeExpired` 以及后台异步命中批量落盘，消除 `SQLITE_BUSY` 写锁争用；
  - `readerDB`：`journal_mode(WAL)`、`query_only(ON)`、`MaxOpenConns(4)`（可通过 `memory.reader_max_open_conns` 调整）—— 专供热路径并发只读检索。
- **存量旧库幂等迁移（`R3.2.1`）**：启动时基于 `PRAGMA table_info(memory_facts)` 检查存量列，按需执行幂等 `ALTER TABLE memory_facts ADD COLUMN` 补齐 `pinned`、`valid_to`、`superseded_by`、`dormant_reason`、`source_quote`、`last_served_at`、`served_count` 与 `created_at_unix`，确保 `R3.2` 旧库平滑升级零报错。同时将 `memory_facts_au` 触发器收敛为 `AFTER UPDATE OF fact, tags`，避免后台刷新 `served_count` 时触发无意义的 FTS5 重分词。

### 2.2 纯 Go 中文 FTS5 全文检索 (`tokenize='trigram'`)
SQLite 默认的 `unicode61` 分词器无法切分无空格的连续中文句子。
- **决策**：在 `memory_facts_fts` 虚表启用 SQLite 内置 `tokenize='trigram'`（纯 Go `modernc.org/sqlite` 原生支持，保持 `CGO_ENABLED=0`）。
- **查询适配**：连续中文问句自动切分为最多 12 个 3-rune 滑动窗口词项并双引号转义，以 `OR` 拼接交由 BM25 排序；不足 3 字符的独立短词（如 `"Go"`）自动回退到带 `client_name` 隔离的参数化 `LIKE` 检索。

### 2.3 Prefix-Cache 友好的双区上下文注入 (`R3.2.1`)
为保护本地 Ollama / `llama.cpp` / vLLM 及云端 OpenAI / DeepSeek 的多轮对话 Prefix Cache，上下文注入拆分为两个独立区域：
- **Zone 1 —— 确定性静态前缀区（`messages[0]`）**：
  - 查询当前 `client_name` 下有效且活跃的 `pinned = 1` 常驻规则（上限由 `memory.max_pinned_facts` 控制，默认 `10`），**严格按 `id ASC` 升序排列**渲染为 `[EdgeCat Pinned Rules]` 并通过 `PrependSystemMessage` 置于 `messages[0]`。只要常驻规则集合未变，跨轮次产出的前缀字节保持 100% 恒定。
- **Zone 2 —— 动态尾插上下文区（最后一条 `user` 消息之前）**：
  - 将 `SearchFacts`（仅返回 `pinned = 0` 条目，避免与 Zone 1 重复占配额）与未过期的 `ListShortTerm` 渲染为 `[EdgeCat Dynamic Context]`。
  - 通过 `proxy.Request.InsertSystemBeforeLastUser` 作为一条 `role: "system"` 消息插入到**最后一条 `role == "user"` 消息紧前面**（若请求不含 `user` 消息则追加到末尾）。在 `[system, user1, assistant1, user2]` 多轮对话中，序列化结果为 `[PinnedRules, system, user1, assistant1, DynamicContext, user2]`，确保 `messages[0..3]` 历史前缀字节在不同追问下完全不变。
- **可观测诊断**：每次请求在 `meta.Values` 中写入 `memory_pinned_injected`、`memory_facts_injected` 与 `memory_short_term_injected`。

### 2.4 时序替代链、幂等写入与历史命中追新 (`R3.2.1`)
- **幂等去重写入（`AddFact` / `AddFactWithMeta`）**：同一 `client_name` 下若已存在脱敏后 `fact` 文本完全一致且当前有效（`valid_to IS NULL AND superseded_by IS NULL`）的记录，直接幂等返回已有 `id`（若新调用指定了 `Pinned: true`、更新了 `SourceQuote` 或原记录处于休眠态，则在原记录上原地升级/唤醒），避免重复堆积相同事实。
- **原子时序替代（`SupersedeFact`）**：在 `writerDB` 单事务内校验 `oldID` 归属当前 `client_name`（不存在或跨租户返回 `ErrFactNotFound`）且尚未被替代（已被替代返回 `ErrFactConflict`，杜绝分叉链），插入脱敏后的 `newFact` 并将旧记录更新为 `valid_to = now, superseded_by = newID`。
- **检索自动追新（搜旧词、得新值）**：若用户提问词法命中了已被替代的旧事实（`superseded_by IS NOT NULL`），`SearchFacts` 沿 `superseded_by` 指针向后追踪最新有效后继并按 `id` 去重；每跳均强制校验 `WHERE client_name = ?`，且严格限制最大跳数 `<= 5` 配合环路检测集合防止死锁。

### 2.5 无锁异步命中追踪与冷记忆休眠原语 (`R3.2.1`)
- **有界非阻塞命中刷新器**：`MutatePreMask` 绝不执行写 SQL，而是将被注入的事实 ID 非阻塞投递至容量为 `256` 的缓冲通道；后台单协程在内存中合并增量后经 `writerDB` 批量更新 `served_count` 与单调递增的 `last_served_at`，并在 `Close()` 时排空落盘后安全退出。队列满时直接丢弃计数事件（记录 `DroppedHitCount`），绝不反压阻塞推理请求。
- **旁路休眠与唤醒原语**：
  - `SweepDormantUnused(ctx, maxIdle)`：将超过 `maxIdle`（对比 `COALESCE(last_served_at, created_at_unix)`）未命中的 `pinned = 0` 活跃事实标记为 `dormant_reason = 'unused'`，`pinned = 1` 常驻规则永不自动休眠；
  - `MarkQuoteMissing(ctx, clientName, factID)`：供外部引文校验任务将归属 `clientName` 且 `pinned = 0` 的失锚事实标记为 `dormant_reason = 'quote_missing'`；
  - `WakeFact(ctx, clientName, factID)`：在校验 `clientName` 归属后清除 `dormant_reason = ''` 并刷新 `last_served_at`。

### 2.6 强制命名空间隔离与零明文 PII 落盘
- 所有查询、替代、休眠、唤醒与命中统计 SQL 均强制绑定 `WHERE client_name = ?`，防止跨客户端越权读取或篡改。
- 所有持久化文本字段（`fact`、`tags`、`source_quote` 及短期 `summary`）入库前一律经过 `sanitizeForStorage`（`filter.Masker` 及可选 `HMAC-SHA256` 稳定占位符 `{{EC_PII_<TYPE>_<16hex>}}`）脱敏。

---

## 3. 配置与热路径保护

`memory.enabled` 默认 **`false`** —— 未显式开启时不打开任何数据库文件，也不注册任何 Mutator：

```yaml
filter:
  enabled: true
  hmac_secret: "${EDGECAT_PII_HMAC_SECRET}" # 可选：启用跨请求 HMAC-SHA256 稳定 PII 键

memory:
  enabled: true
  sqlite_path: "data/edgecat_memory.db"
  max_pinned_facts: 10            # Zone 1 静态常驻前缀上限（按 id ASC 注入 messages[0]）
  max_facts: 5                    # Zone 2 动态检索事实上限
  max_short_term: 3               # Zone 2 近期滚动摘要上限
  query_timeout_ms: 50            # 热路径检索超时预算（超时静默放行）
  reader_max_open_conns: 4        # 只读检索连接池大小
  prepend_dynamic_context: false  # 兼容开关：仅在上游模型拒绝对话中间出现 system 角色时设为 true
```

- **TTFT 故障放行（Fail-Open）**：`MutatePreMask` 零网络/零模型调用，且受 `query_timeout_ms`（默认 `50ms`）严格超时限制；读库超时或报错时仅记录日志并返回 `nil`。
- **PreMask 隐私审查**：Zone 1 与 Zone 2 消息均在 `StagePreMask` 阶段注入，发出前仍统一受网关 PII 出境策略检查。

---

## 4. 代价与边界说明 (Trade-Offs & Boundaries)

- **中间 `system` 消息的模型模板兼容性边界（`prepend_dynamic_context`）**：将 Zone 2 作为 `role: "system"` 插在最后一条 `user` 消息之前，能让 OpenAI、DeepSeek、Qwen 及主流 Ollama / `llama.cpp` 模型跨轮复用整段历史 KV Cache；但少数极端非标或旧版 Jinja 聊天模板强制要求 `system` 消息只能出现在 `messages[0]` 且后续严格 `user/assistant` 交替，遇到中间 `system` 消息会返回 400 错误。针对此类非标模型，可将 `memory.prepend_dynamic_context` 设为 `true`，使 Zone 2 回退至 `messages[1]`（紧随 Zone 1 之后），代价是放弃多轮历史消息的 Prefix Cache 稳定性。
- **5 跳追新上限边界**：`SearchFacts` 对 `superseded_by` 链路的向后追踪硬限制为最多 `5` 跳。若某条事实连续演进超过 5 代，且用户提问仅包含第 1 代的旧专有词（后续代数均未出现该词），检索将在第 5 跳处停止而不再继续追查，以此换取热路径 `<50ms` 的确定性延迟上限；超长演进链可由离线维护脚本定期压缩归并。
- **极端突发流量下的近似命中计数**：异步命中通道容量固定（默认 `256`）且永不阻塞请求；当瞬时并发远超单写连接落盘吞吐时，溢出的 `served_count` 增量会被主动丢弃。该计数仅服务于冷记忆休眠治理，不作为精确计费账本。
- **3 字符 Trigram 下限与外部蒸馏职责边界**：SQLite `trigram` 分词要求至少 3 个连续字符重合（不足 3 字符的独立短查询走 `LIKE` 回退）；事实提炼、`SupersedeFact` 演进与周期性 `SweepDormantUnused` / `MarkQuoteMissing` 巡检均由外部任务或旁路脚本驱动，网关热路径绝不夹带额外 LLM 调用。
- **离线副本威胁模型**：与 [ADR-0002](0002-positioning-and-homelab-governance_zh.md) 一致，`edgecat_memory.db` 不引入需要 CGO 的 SQLCipher 全库加密，数据安全依赖入库前强制 PII 脱敏保障。
