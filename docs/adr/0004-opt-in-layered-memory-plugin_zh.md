# ADR-0004: 可选分层记忆插件与跨请求 HMAC 稳定 PII 键设计 (R3.2)

<p align="center">
  <a href="0004-opt-in-layered-memory-plugin.md">English</a> •
  <b>中文</b>
</p>

- **状态**: Accepted & Implemented (已通过并落地 `R3.2`)
- **日期**: 2026-11-20
- **决策人**: 郭强 (Guo Qiang)
- **涉及模块**: `internal/memory/plugin.go`, `internal/filter/pii.go`, `internal/config/config.go`, `internal/proxy/handler.go`, `cmd/edgecat/main.go`

---

## 1. 背景与核心问题 (Context)

在 [ADR-0002](0002-positioning-and-homelab-governance_zh.md) 中，EdgeCat 为任何有状态的记忆能力划定了两条硬红线：
1. **绝不破坏 `CGO_ENABLED=0`**：不引入 C++ 中文分词库、`mattn/go-sqlite3` 或 SQLCipher；
2. **绝不落盘明文 PII**：记忆能力必须默认关闭（Opt-in），在家庭/内网多端共享场景下强制按客户端隔离命名空间，并且只能以 [ADR-0003](0003-two-stage-request-mutator_zh.md) 定义的 `RequestMutator` 插件形态挂载，绝不侵入网关主循环。

为验证 `RequestMutator` 扩展契约并给出生产级参考实现，**R3.2** 落地了可选分层记忆插件（`internal/memory`）以及跨请求稳定 PII 键（`filter.NewStableVault`）。

---

## 2. 架构决策

### 2.1 SQLite 读写双句柄分离 (Writer / Reader Pool Separation)
如果让热路径 `StagePreMask` 检索与写入共享同一个 `MaxOpenConns(1)` 连接，所有并发推理请求都会在写入事务后排队。
- **决策**：针对同一份 WAL 模式数据库（`data/edgecat_memory.db`）建立两个独立连接池：
  - `writerDB`：`journal_mode(WAL)`、`synchronous(NORMAL)`、`MaxOpenConns(1)` —— 串行承接 `AddFact`、`AddShortTerm`、`PurgeExpired`，消除 `SQLITE_BUSY` 写锁冲突；
  - `readerDB`：`journal_mode(WAL)`、`query_only(ON)`、`MaxOpenConns(4)`（可通过 `memory.reader_max_open_conns` 调整）—— 专供热路径并发只读检索，不被写入阻塞。

### 2.2 纯 Go 中文 FTS5 全文检索 (`tokenize='trigram'`)
SQLite 默认的 `unicode61` 分词器无法切分无空格的连续中文句子。
- **决策**：在 `memory_facts_fts` 虚表显式启用 SQLite 内置 `tokenize='trigram'`（纯 Go `modernc.org/sqlite` 原生支持，保持 `CGO_ENABLED=0`），通过 `AFTER INSERT / UPDATE / DELETE` 触发器保持与主表 `memory_facts` 同步。
- **查询适配**：连续中文问句自动切分为最多 12 个 3-rune 滑动窗口词项并双引号转义，以 `OR` 拼接交由 BM25 排序，彻底杜绝标点导致的 FTS5 语法错误；对于不足 3 字符的短词（如 `"Go"`），自动回退到带 `client_name` 隔离的参数化 `LIKE` 检索。

### 2.3 分层存储、命名空间硬隔离与 HMAC 稳定键
- **两层记忆结构**：
  1. `memory_facts`：长期蒸馏后的非敏感事实，建有 FTS5 `trigram` 索引；
  2. `memory_short_term`：带 `expires_at` Unix 时间戳的短期滚动摘要（配合 `PurgeExpired` 清理过期条目）。
- **强制 `client_name` 命名空间隔离**：所有读写 SQL 均强制绑定 `WHERE client_name = ?`，多端内网共享时 `alice` 绝不可能检索到 `bob` 的任何记忆。
- **零明文 PII 落盘与跨请求稳定键**：
  - 写入 `memory_facts` 或 `memory_short_term` 前强制经过 `filter.Masker` 脱敏；
  - 当配置了 `filter.hmac_secret` 时，`filter.NewStableVault` 取 `HMAC-SHA256(原文, 本地密钥)` 前 8 字节（16 位小写十六进制）生成跨请求一致的稳定占位符 `{{EC_PII_<TYPE>_<16hex>}}`；
  - 同一敏感实体在不同请求和记忆库中映射到完全相同的占位符，且 `SlidingRehydrator` 原生支持跨 SSE 分片无损还原。

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
  max_facts: 5
  max_short_term: 3
  query_timeout_ms: 50
  reader_max_open_conns: 4
```

- **TTFT 故障放行（Fail-Open）**：`MutatePreMask` 严格受 `query_timeout_ms`（默认 `50ms`）上下文超时约束；一旦超时或读库异常，仅记录告警日志并返回 `nil`，绝不阻塞正常对话推理。
- **PreMask 隐私护栏闭环**：注入的 `[EdgeCat Memory Context]` 系统消息位于 `StagePreMask` 阶段，发出前仍会统一受 EdgeCat PII 策略审查。

---

## 4. 代价与边界说明 (Trade-Offs & Boundaries)

- **3 字符 Trigram 匹配下限**：SQLite `trigram` 分词器要求至少 3 个连续字符重合；嵌入在长句中的 2 字中文词不会命中 FTS5（独立短词会自动走 `LIKE` 回退）。
- **蒸馏解耦**：遵循 EdgeCat 的 Non-Goals 边界，插件不在代理热路径里额外发起 LLM 调用做自动蒸馏；事实与短期摘要由外部离线任务或本地工作流显式通过 `AddFact` / `AddShortTerm` 写入。
- **离线副本威胁模型**：与 [ADR-0002](0002-positioning-and-homelab-governance_zh.md) 一致，`memory.db` 不做 SQLCipher 全库加密（以保留 `CGO_ENABLED=0` 与 FTS5），安全性依靠“入库前强制脱敏、绝不落盘明文 PII”来保障。
