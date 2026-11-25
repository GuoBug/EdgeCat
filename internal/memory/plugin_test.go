// Package memory_test verifies EdgeCat's opt-in layered memory plugin (R3.2).
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package memory_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/patchcat-dev/edgecat/internal/audit"
	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/contract"
	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/memory"
	"github.com/patchcat-dev/edgecat/internal/proxy"
	"github.com/patchcat-dev/edgecat/internal/quota"
	"github.com/patchcat-dev/edgecat/internal/router"
)

func TestLayeredMemory_DualPools_TrigramCJK_And_ClientNamespaceIsolation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "memory.db")
	secret := []byte("homelab-local-secret")
	masker := filter.NewMasker(true, true, true, true)

	plugin, err := memory.NewPlugin(memory.Options{
		SQLitePath:         dbPath,
		MaxFacts:           5,
		MaxShortTerm:       3,
		QueryTimeoutMs:     200,
		ReaderMaxOpenConns: 4,
		Masker:             masker,
		HMACSecret:         secret,
	})
	if err != nil {
		t.Fatalf("NewPlugin failed: %v", err)
	}
	defer func() { _ = plugin.Close() }()

	// 1. Verify separate Writer (1) and Reader (4) pool configurations.
	if plugin.WriterMaxOpenConns() != 1 {
		t.Fatalf("expected writer MaxOpenConns=1, got %d", plugin.WriterMaxOpenConns())
	}
	if plugin.ReaderMaxOpenConns() != 4 {
		t.Fatalf("expected reader MaxOpenConns=4, got %d", plugin.ReaderMaxOpenConns())
	}

	ctx := context.Background()

	// 2. Store Chinese facts under two isolated namespaces (alice vs bob).
	if _, err := plugin.AddFact(ctx, "alice", "用户偏好使用 Go 语言和深色主题", "preference"); err != nil {
		t.Fatalf("AddFact alice #1: %v", err)
	}
	if _, err := plugin.AddFact(ctx, "alice", "家庭 NAS 部署在 Synology 上", "homelab"); err != nil {
		t.Fatalf("AddFact alice #2: %v", err)
	}
	if _, err := plugin.AddFact(ctx, "bob", "Bob 拒绝深色主题，只用浅色主题和 Python", "preference"); err != nil {
		t.Fatalf("AddFact bob #1: %v", err)
	}

	// 3. Continuous Chinese sentence query via FTS5 trigram tokenizer.
	facts, err := plugin.SearchFacts(ctx, "alice", "帮我推荐一个深色主题编辑器", 5)
	if err != nil {
		t.Fatalf("SearchFacts CJK failed: %v", err)
	}
	if len(facts) != 1 || facts[0].ClientName != "alice" || !strings.Contains(facts[0].Fact, "Go 语言和深色主题") {
		t.Fatalf("expected only alice's dark-theme fact, got: %+v", facts)
	}

	// 4. Short <3-rune query ("Go") falls back cleanly to LIKE scoped to alice.
	shortFacts, err := plugin.SearchFacts(ctx, "alice", "Go", 5)
	if err != nil {
		t.Fatalf("SearchFacts short query failed: %v", err)
	}
	if len(shortFacts) != 1 || !strings.Contains(shortFacts[0].Fact, "Go 语言") {
		t.Fatalf("expected Go fact via LIKE fallback, got: %+v", shortFacts)
	}

	// 5. Namespace isolation: both alice and bob match trigram "深色主题",
	//    but bob must NEVER see alice's fact.
	bobFacts, err := plugin.SearchFacts(ctx, "bob", "帮我选一个深色主题方案", 5)
	if err != nil {
		t.Fatalf("SearchFacts bob failed: %v", err)
	}
	if len(bobFacts) != 1 || bobFacts[0].ClientName != "bob" || !strings.Contains(bobFacts[0].Fact, "Bob 拒绝深色主题") {
		t.Fatalf("namespace isolation violated for bob: %+v", bobFacts)
	}

	// 6. Malformed FTS5 punctuation must never trigger SQL syntax errors.
	if _, err := plugin.SearchFacts(ctx, "alice", `"unclosed * -test: (123)`, 5); err != nil {
		t.Fatalf("FTS5 query sanitization failed: %v", err)
	}
}

func TestLayeredMemory_PIISanitizationWithStableHMACKeyAndShortTermTTL(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "memory_pii.db")
	secret := []byte("my-local-hmac-key")
	masker := filter.NewMasker(true, true, true, true)

	plugin, err := memory.NewPlugin(memory.Options{
		SQLitePath: dbPath,
		Masker:     masker,
		HMACSecret: secret,
	})
	if err != nil {
		t.Fatalf("NewPlugin failed: %v", err)
	}
	defer func() { _ = plugin.Close() }()

	ctx := context.Background()
	const rawPhone = "13800138000"
	expectedPlaceholder := "{{EC_PII_PHONE_" + filter.StableKey(rawPhone, secret) + "}}"

	if _, err := plugin.AddFact(ctx, "alice", "运维联系人电话是 "+rawPhone+" 负责家庭NAS", "ops"); err != nil {
		t.Fatalf("AddFact with PII: %v", err)
	}

	// Verify raw SQLite table NEVER contains plaintext phone number.
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer rawDB.Close()

	var storedFact string
	if err := rawDB.QueryRow(`SELECT fact FROM memory_facts WHERE client_name = 'alice' LIMIT 1`).Scan(&storedFact); err != nil {
		t.Fatalf("scan stored fact: %v", err)
	}
	if strings.Contains(storedFact, rawPhone) {
		t.Fatalf("plaintext PII persisted to SQLite: %q", storedFact)
	}
	if !strings.Contains(storedFact, expectedPlaceholder) {
		t.Fatalf("expected stable HMAC placeholder %q in stored fact, got %q", expectedPlaceholder, storedFact)
	}

	// Verify short-term TTL expiry & purge.
	if _, err := plugin.AddShortTerm(ctx, "alice", "正在调试 EdgeCat 网关", 10*time.Minute); err != nil {
		t.Fatalf("AddShortTerm active: %v", err)
	}
	if _, err := rawDB.Exec(`INSERT INTO memory_short_term (client_name, summary, expires_at) VALUES ('alice', '已过期的临时对话', ?)`, time.Now().Add(-1*time.Minute).Unix()); err != nil {
		t.Fatalf("insert expired row: %v", err)
	}

	active, err := plugin.ListShortTerm(ctx, "alice", 5)
	if err != nil {
		t.Fatalf("ListShortTerm: %v", err)
	}
	if len(active) != 1 || active[0].Summary != "正在调试 EdgeCat 网关" {
		t.Fatalf("expected only 1 active short-term entry, got %+v", active)
	}

	purged, err := plugin.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 expired row purged, got %d", purged)
	}
}

func TestLayeredMemory_EndToEndProxyMutatorIntegration(t *testing.T) {
	var upstreamBody []byte
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		upstreamBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-mem","choices":[{"index":0,"message":{"role":"assistant","content":"已收到"}}]}`))
	}))
	defer cloud.Close()

	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = ""
	cfg.Cloud.Endpoint = cloud.URL
	cfg.Auth.Enabled = true
	cfg.Auth.Clients = []config.ClientConfig{
		{Name: "alice", Token: "tok-alice"},
		{Name: "bob", Token: "tok-bob"},
	}
	cfg.Filter.Enabled = true
	cfg.Filter.HMACSecret = "integration-secret"

	auditLogger, err := audit.NewLogger(filepath.Join(tmpDir, "audit.db"), 10, 100, 100)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	qm, err := quota.NewManager(auditLogger.DB(), cfg.Auth.Clients)
	if err != nil {
		t.Fatalf("quota manager: %v", err)
	}
	masker := filter.NewMasker(true, true, true, true)
	guard := contract.NewGuard(false, 1, 5000)

	memPlugin, err := memory.NewPlugin(memory.Options{
		SQLitePath: filepath.Join(tmpDir, "memory.db"),
		Masker:     masker,
		HMACSecret: []byte(cfg.Filter.HMACSecret),
	})
	if err != nil {
		t.Fatalf("memory plugin: %v", err)
	}
	t.Cleanup(func() { _ = memPlugin.Close() })

	ctx := context.Background()
	_, _ = memPlugin.AddFact(ctx, "alice", "用户正在开发 EdgeCat 本地推理网关", "project")
	_, _ = memPlugin.AddFact(ctx, "bob", "Bob 的私密项目计划", "secret")

	h := proxy.NewHandler(
		cfg, masker, router.NewRouter(cfg), guard, auditLogger, qm,
		proxy.WithRequestMutators(memPlugin),
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{
		"model": "default",
		"messages": [{"role": "user", "content": "帮我总结 EdgeCat 本地推理网关的亮点"}],
		"stream": false
	}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok-alice")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	upstreamStr := string(upstreamBody)
	if !strings.Contains(upstreamStr, "用户正在开发 EdgeCat 本地推理网关") {
		t.Fatalf("expected alice's memory fact injected into upstream system message, got: %s", upstreamStr)
	}
	if strings.Contains(upstreamStr, "Bob 的私密项目计划") {
		t.Fatalf("bob's private memory leaked into alice's request: %s", upstreamStr)
	}
}

func TestLayeredMemory_IdempotentLegacySchemaMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy_r32.db")

	// 1. Construct a strict R3.2 legacy schema (without R3.2.1 governance columns).
	legacyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	legacyDDL := `
	CREATE TABLE memory_facts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_name TEXT NOT NULL,
		fact TEXT NOT NULL,
		tags TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE VIRTUAL TABLE memory_facts_fts USING fts5(
		fact, tags, content='memory_facts', content_rowid='id', tokenize='trigram'
	);
	CREATE TRIGGER memory_facts_ai AFTER INSERT ON memory_facts BEGIN
		INSERT INTO memory_facts_fts(rowid, fact, tags) VALUES (new.id, new.fact, new.tags);
	END;
	INSERT INTO memory_facts (client_name, fact, tags) VALUES ('alice', '存量旧库中的家庭网关配置事实', 'legacy');
	`
	if _, err := legacyDB.Exec(legacyDDL); err != nil {
		_ = legacyDB.Close()
		t.Fatalf("seed legacy schema: %v", err)
	}
	_ = legacyDB.Close()

	// 2. Open with R3.2.1 NewPlugin twice to verify idempotent ALTER TABLE migration.
	for attempt := 1; attempt <= 2; attempt++ {
		plugin, err := memory.NewPlugin(memory.Options{SQLitePath: dbPath})
		if err != nil {
			t.Fatalf("NewPlugin migration attempt #%d failed: %v", attempt, err)
		}

		ctx := context.Background()
		facts, err := plugin.SearchFacts(ctx, "alice", "家庭网关配置", 5)
		if err != nil {
			_ = plugin.Close()
			t.Fatalf("SearchFacts after migration #%d failed: %v", attempt, err)
		}
		if len(facts) != 1 || facts[0].Pinned || facts[0].DormantReason != "" || facts[0].ServedCount != 0 {
			_ = plugin.Close()
			t.Fatalf("unexpected migrated legacy fact on attempt #%d: %+v", attempt, facts)
		}
		if err := plugin.Close(); err != nil {
			t.Fatalf("Close attempt #%d failed: %v", attempt, err)
		}
	}
}

func TestLayeredMemory_IdempotentAdd_TemporalSupersede_And_LineageChase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lineage.db")
	secret := []byte("lineage-hmac-secret")
	masker := filter.NewMasker(true, true, true, true)

	plugin, err := memory.NewPlugin(memory.Options{
		SQLitePath: dbPath,
		Masker:     masker,
		HMACSecret: secret,
	})
	if err != nil {
		t.Fatalf("NewPlugin: %v", err)
	}
	defer func() { _ = plugin.Close() }()

	ctx := context.Background()

	// 1. Idempotent AddFact deduplication & metadata promotion + PII redaction on source_quote.
	id1, err := plugin.AddFact(ctx, "alice", "主力开发环境是 Go 1.26", "env")
	if err != nil {
		t.Fatalf("AddFact #1: %v", err)
	}
	idDup, err := plugin.AddFact(ctx, "alice", "  主力开发环境是 Go 1.26  ", "env")
	if err != nil {
		t.Fatalf("AddFact duplicate: %v", err)
	}
	if idDup != id1 {
		t.Fatalf("expected idempotent duplicate ID %d, got %d", id1, idDup)
	}

	// Same text for bob must allocate a distinct row in bob's isolated namespace.
	bobID, err := plugin.AddFact(ctx, "bob", "主力开发环境是 Go 1.26", "env")
	if err != nil || bobID == id1 {
		t.Fatalf("expected distinct ID for bob, got id=%d err=%v", bobID, err)
	}

	// Promote alice's fact with Pinned=true and a PII-containing SourceQuote.
	const rawEmail = "ops@example.com"
	promotedID, err := plugin.AddFactWithMeta(ctx, "alice", "主力开发环境是 Go 1.26", memory.FactMeta{
		Pinned:      true,
		SourceQuote: "引自配置文档联系人 " + rawEmail,
	})
	if err != nil || promotedID != id1 {
		t.Fatalf("expected in-place promotion of ID %d, got %d (err=%v)", id1, promotedID, err)
	}
	gotPromoted, err := plugin.GetFact(ctx, "alice", id1)
	if err != nil {
		t.Fatalf("GetFact: %v", err)
	}
	if !gotPromoted.Pinned || strings.Contains(gotPromoted.SourceQuote, rawEmail) || !strings.Contains(gotPromoted.SourceQuote, "{{EC_PII_EMAIL_") {
		t.Fatalf("expected Pinned=true and sanitized SourceQuote, got %+v", gotPromoted)
	}

	// 2. Cross-client SupersedeFact tampering MUST fail with ErrFactNotFound.
	v1, err := plugin.AddFact(ctx, "alice", "项目数据库早期采用 PostgreSQL 14", "db")
	if err != nil {
		t.Fatalf("AddFact v1: %v", err)
	}
	if _, err := plugin.SupersedeFact(ctx, "bob", v1, "恶意篡改 Alice 的记忆", "attack"); !errors.Is(err, memory.ErrFactNotFound) {
		t.Fatalf("expected ErrFactNotFound on cross-client supersede, got %v", err)
	}

	// 3. Build a 5-hop supersede chain: v1 -> v2 -> v3 -> v4 -> v5 -> v6.
	curr := v1
	for step := 2; step <= 5; step++ {
		next, err := plugin.SupersedeFact(ctx, "alice", curr, fmt.Sprintf("数据库演进中间态版本 v%d", step), "db")
		if err != nil {
			t.Fatalf("SupersedeFact step %d: %v", step, err)
		}
		curr = next
	}
	v6, err := plugin.SupersedeFact(ctx, "alice", curr, "最终迁移至纯 Go SQLite WAL 双池架构", "db")
	if err != nil {
		t.Fatalf("SupersedeFact v6: %v", err)
	}

	// Attempting to supersede v1 again must fail with ErrFactConflict (no forked chains).
	if _, err := plugin.SupersedeFact(ctx, "alice", v1, "分叉冲突写入", "db"); !errors.Is(err, memory.ErrFactConflict) {
		t.Fatalf("expected ErrFactConflict when superseding an already-superseded fact, got %v", err)
	}

	// Querying the old keyword "PostgreSQL" (only in v1!) must chase 5 hops and return v6 once.
	hits, err := plugin.SearchFacts(ctx, "alice", "之前 PostgreSQL 数据库现在是什么架构", 5)
	if err != nil {
		t.Fatalf("SearchFacts lineage chase: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != v6 || !strings.Contains(hits[0].Fact, "SQLite WAL 双池架构") {
		t.Fatalf("expected single deduplicated terminal fact v6 (%d), got %+v", v6, hits)
	}

	// 4. Hop cap (>5 hops) & cycle/cross-client tampering defense.
	// Extending v6 -> v7 makes v1 -> ... -> v7 a 6-hop chain: querying "PostgreSQL" must stop at 5 hops.
	_, err = plugin.SupersedeFact(ctx, "alice", v6, "超过五跳上限的第七代事实", "db")
	if err != nil {
		t.Fatalf("SupersedeFact v7: %v", err)
	}
	overCapHits, err := plugin.SearchFacts(ctx, "alice", "PostgreSQL", 5)
	if err != nil {
		t.Fatalf("SearchFacts over-cap: %v", err)
	}
	if len(overCapHits) != 0 {
		t.Fatalf("expected 0 results when lineage exceeds 5 hops, got %+v", overCapHits)
	}

	// Inject a corrupted cycle (c1 <-> c2) and a tampered cross-client pointer directly in SQLite.
	cyc1, _ := plugin.AddFact(ctx, "alice", "环路测试旧词 AlphaCycle", "cycle")
	cyc2, _ := plugin.AddFact(ctx, "alice", "环路测试节点 BetaCycle", "cycle")
	crossSrc, _ := plugin.AddFact(ctx, "alice", "跨租户指针测试 CrossPointer", "sec")
	bobSecret, _ := plugin.AddFact(ctx, "bob", "Bob 绝密后继事实", "sec")

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer rawDB.Close()
	_, _ = rawDB.Exec(`UPDATE memory_facts SET valid_to = 1, superseded_by = ? WHERE id = ?`, cyc2, cyc1)
	_, _ = rawDB.Exec(`UPDATE memory_facts SET valid_to = 1, superseded_by = ? WHERE id = ?`, cyc1, cyc2)
	_, _ = rawDB.Exec(`UPDATE memory_facts SET valid_to = 1, superseded_by = ? WHERE id = ?`, bobSecret, crossSrc)

	cycHits, err := plugin.SearchFacts(ctx, "alice", "AlphaCycle", 5)
	if err != nil || len(cycHits) != 0 {
		t.Fatalf("expected safe cycle termination with 0 hits, got hits=%+v err=%v", cycHits, err)
	}
	crossHits, err := plugin.SearchFacts(ctx, "alice", "CrossPointer", 5)
	if err != nil || len(crossHits) != 0 {
		t.Fatalf("expected cross-client superseded_by pointer to be blocked, got hits=%+v err=%v", crossHits, err)
	}
}

func TestLayeredMemory_TwoZonePrefixCacheDeterminism_And_FallbackToggle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "prefix_cache.db")
	plugin, err := memory.NewPlugin(memory.Options{
		SQLitePath:     dbPath,
		MaxPinnedFacts: 10,
		MaxFacts:       5,
		MaxShortTerm:   3,
	})
	if err != nil {
		t.Fatalf("NewPlugin: %v", err)
	}
	defer func() { _ = plugin.Close() }()

	ctx := context.Background()

	// Add 2 pinned rules and 2 distinct unpinned dynamic facts + 1 short-term summary.
	_, _ = plugin.AddFactWithMeta(ctx, "alice", "代码注释与对外文档统一使用中文或英文专业术语", memory.FactMeta{Pinned: true, Tags: "rule"})
	_, _ = plugin.AddFactWithMeta(ctx, "alice", "严禁引入任何 CGO 依赖，保持纯静态单二进制编译", memory.FactMeta{Pinned: true, Tags: "rule"})
	_, _ = plugin.AddFact(ctx, "alice", "本地网关默认监听端口为 8080", "network")
	_, _ = plugin.AddFact(ctx, "alice", "首字节超时预算默认设置为 3500 毫秒", "router")
	_, _ = plugin.AddShortTerm(ctx, "alice", "正在排查多轮对话 KV Cache 命中率问题", 10*time.Minute)

	makeMultiTurnReq := func(user2Question string) *proxy.Request {
		payload := fmt.Sprintf(`{
			"model": "default",
			"messages": [
				{"role": "system", "content": "You are a helpful homelab assistant."},
				{"role": "user", "content": "你好，先对齐一下当前网关工作区"},
				{"role": "assistant", "content": "好的，请告诉我你想了解哪个模块？"},
				{"role": "user", "content": %q}
			]
		}`, user2Question)
		r, err := proxy.ParseRequest([]byte(payload))
		if err != nil {
			t.Fatalf("ParseRequest: %v", err)
		}
		return r
	}

	reqA := makeMultiTurnReq("请问本地网关默认监听端口是多少？")
	metaA := &proxy.RequestMeta{ClientName: "alice", Stage: proxy.StagePreMask, Values: make(map[string]any)}
	if err := plugin.MutatePreMask(ctx, reqA, metaA); err != nil {
		t.Fatalf("MutatePreMask A: %v", err)
	}

	reqB := makeMultiTurnReq("请问首字节超时预算默认设置是多少？")
	metaB := &proxy.RequestMeta{ClientName: "alice", Stage: proxy.StagePreMask, Values: make(map[string]any)}
	if err := plugin.MutatePreMask(ctx, reqB, metaB); err != nil {
		t.Fatalf("MutatePreMask B: %v", err)
	}

	msgsA := reqA.Messages()
	msgsB := reqB.Messages()
	if len(msgsA) != 6 || len(msgsB) != 6 {
		t.Fatalf("expected 6 messages ([Pinned, sys, u1, a1, Dynamic, u2]), got lenA=%d lenB=%d", len(msgsA), len(msgsB))
	}

	// Assert messages[0..3] serialize to 100% identical bytes across both turns despite different dynamic facts!
	prefixBytesA, err := json.Marshal(msgsA[:4])
	if err != nil {
		t.Fatalf("marshal prefix A: %v", err)
	}
	prefixBytesB, err := json.Marshal(msgsB[:4])
	if err != nil {
		t.Fatalf("marshal prefix B: %v", err)
	}
	if !bytes.Equal(prefixBytesA, prefixBytesB) {
		t.Fatalf("Prefix Cache broken! messages[0..3] bytes differ:\nA=%s\nB=%s", prefixBytesA, prefixBytesB)
	}

	// Verify Zone 1 sits at messages[0] in strict id ASC order.
	zone1Content := msgsA[0].(map[string]any)["content"].(string)
	idxRule1 := strings.Index(zone1Content, "代码注释与对外文档")
	idxRule2 := strings.Index(zone1Content, "严禁引入任何 CGO 依赖")
	if !strings.HasPrefix(zone1Content, "[EdgeCat Pinned Rules]") || idxRule1 < 0 || idxRule2 <= idxRule1 {
		t.Fatalf("unexpected Zone 1 pinned content/order: %q", zone1Content)
	}

	// Verify Zone 2 lands at index 4 (immediately before user2 at index 5) and excludes pinned facts.
	dynA := msgsA[4].(map[string]any)
	dynB := msgsB[4].(map[string]any)
	if dynA["role"] != "system" || !strings.Contains(dynA["content"].(string), "8080") || strings.Contains(dynA["content"].(string), "CGO") {
		t.Fatalf("unexpected Zone 2 for reqA: %+v", dynA)
	}
	if dynB["role"] != "system" || !strings.Contains(dynB["content"].(string), "3500") || strings.Contains(dynB["content"].(string), "CGO") {
		t.Fatalf("unexpected Zone 2 for reqB: %+v", dynB)
	}
	if msgsA[5].(map[string]any)["role"] != "user" || !strings.Contains(msgsA[5].(map[string]any)["content"].(string), "默认监听端口") {
		t.Fatalf("expected user2 at messages[5], got %+v", msgsA[5])
	}

	// Verify meta.Values diagnostic counters.
	if metaA.Values["memory_pinned_injected"] != 2 || metaA.Values["memory_facts_injected"] != 1 || metaA.Values["memory_short_term_injected"] != 1 {
		t.Fatalf("unexpected meta.Values counters: %+v", metaA.Values)
	}

	// Verify PrependDynamicContext compatibility escape hatch places both zones at the front.
	fallbackPlugin, err := memory.NewPlugin(memory.Options{
		SQLitePath:            dbPath,
		PrependDynamicContext: true,
	})
	if err != nil {
		t.Fatalf("NewPlugin fallback: %v", err)
	}
	defer func() { _ = fallbackPlugin.Close() }()

	reqFallback := makeMultiTurnReq("请问本地网关默认监听端口是多少？")
	if err := fallbackPlugin.MutatePreMask(ctx, reqFallback, &proxy.RequestMeta{ClientName: "alice", Values: map[string]any{}}); err != nil {
		t.Fatalf("MutatePreMask fallback: %v", err)
	}
	fbMsgs := reqFallback.Messages()
	if !strings.HasPrefix(fbMsgs[0].(map[string]any)["content"].(string), "[EdgeCat Pinned Rules]") ||
		!strings.HasPrefix(fbMsgs[1].(map[string]any)["content"].(string), "[EdgeCat Dynamic Context]") {
		t.Fatalf("expected [Pinned, Dynamic, ...] when PrependDynamicContext=true, got %+v", fbMsgs[:2])
	}
}

func TestLayeredMemory_Dormancy_QuoteGuard_And_ConcurrentAsyncHitTracking(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "dormancy_race.db")
	plugin, err := memory.NewPlugin(memory.Options{
		SQLitePath:         dbPath,
		HitQueueSize:       256,
		HitFlushIntervalMs: 25,
	})
	if err != nil {
		t.Fatalf("NewPlugin: %v", err)
	}

	ctx := context.Background()

	pinnedID, _ := plugin.AddFactWithMeta(ctx, "alice", "常驻规则永不休眠", memory.FactMeta{Pinned: true})
	staleID, _ := plugin.AddFact(ctx, "alice", "长期无人问津的陈旧部署记录", "old")
	quoteID, _ := plugin.AddFactWithMeta(ctx, "alice", "依赖外部文档锚点的配置说明", memory.FactMeta{SourceQuote: "doc-anchor-v1"})
	hotID, _ := plugin.AddFact(ctx, "alice", "高频命中的核心路由策略说明", "hot")

	// Backdate both pinnedID and staleID by 60 days in SQLite to verify pinned=1 immunity.
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer rawDB.Close()
	sixtyDaysAgo := time.Now().Add(-60 * 24 * time.Hour).Unix()
	if _, err := rawDB.Exec(`UPDATE memory_facts SET created_at_unix = ?, last_served_at = NULL WHERE id IN (?, ?)`, sixtyDaysAgo, pinnedID, staleID); err != nil {
		t.Fatalf("backdate facts: %v", err)
	}

	// 1. SweepDormantUnused must sweep staleID (pinned=0) and NEVER touch pinnedID (pinned=1) or hotID.
	swept, err := plugin.SweepDormantUnused(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("SweepDormantUnused: %v", err)
	}
	if swept != 1 {
		t.Fatalf("expected exactly 1 unpinned stale fact swept, got %d", swept)
	}
	pinnedFact, _ := plugin.GetFact(ctx, "alice", pinnedID)
	staleFact, _ := plugin.GetFact(ctx, "alice", staleID)
	if pinnedFact.DormantReason != "" {
		t.Fatalf("pinned fact must never be swept dormant, got %+v", pinnedFact)
	}
	if staleFact.DormantReason != memory.DormantReasonUnused {
		t.Fatalf("expected stale fact dormant_reason='unused', got %+v", staleFact)
	}
	if hits, _ := plugin.SearchFacts(ctx, "alice", "陈旧部署记录", 5); len(hits) != 0 {
		t.Fatalf("dormant unused fact should be excluded from SearchFacts, got %+v", hits)
	}

	// 2. MarkQuoteMissing & WakeFact with strict client_name isolation.
	if err := plugin.MarkQuoteMissing(ctx, "bob", quoteID); !errors.Is(err, memory.ErrFactNotFound) {
		t.Fatalf("expected ErrFactNotFound on cross-client MarkQuoteMissing, got %v", err)
	}
	if err := plugin.MarkQuoteMissing(ctx, "alice", pinnedID); err != nil {
		t.Fatalf("MarkQuoteMissing on pinned fact should be safe no-op, got %v", err)
	}
	if pf, _ := plugin.GetFact(ctx, "alice", pinnedID); pf.DormantReason != "" {
		t.Fatalf("pinned fact must ignore MarkQuoteMissing, got %+v", pf)
	}
	if err := plugin.MarkQuoteMissing(ctx, "alice", quoteID); err != nil {
		t.Fatalf("MarkQuoteMissing: %v", err)
	}
	if hits, _ := plugin.SearchFacts(ctx, "alice", "外部文档锚点", 5); len(hits) != 0 {
		t.Fatalf("quote_missing fact should be excluded from SearchFacts, got %+v", hits)
	}
	if err := plugin.WakeFact(ctx, "bob", quoteID); !errors.Is(err, memory.ErrFactNotFound) {
		t.Fatalf("expected ErrFactNotFound on cross-client WakeFact, got %v", err)
	}
	if err := plugin.WakeFact(ctx, "alice", quoteID); err != nil {
		t.Fatalf("WakeFact: %v", err)
	}
	if hits, _ := plugin.SearchFacts(ctx, "alice", "外部文档锚点", 5); len(hits) != 1 {
		t.Fatalf("expected woken fact to reappear in SearchFacts, got %+v", hits)
	}

	// 3. Concurrent MutatePreMask hit tracking + graceful Close() drain (race detector verification).
	const workers = 8
	const perWorker = 10
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				req, err := proxy.ParseRequest([]byte(`{"model":"default","messages":[{"role":"user","content":"查询高频命中的核心路由策略说明"}]}`))
				if err != nil {
					t.Errorf("ParseRequest: %v", err)
					return
				}
				meta := &proxy.RequestMeta{ClientName: "alice", Stage: proxy.StagePreMask, Values: map[string]any{}}
				if err := plugin.MutatePreMask(ctx, req, meta); err != nil {
					t.Errorf("MutatePreMask: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// Close drains all queued hit events before closing writerDB.
	if err := plugin.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	const expectedHits = int64(workers * perWorker)
	var servedCount int64
	var lastServed sql.NullInt64
	if err := rawDB.QueryRow(`SELECT served_count, last_served_at FROM memory_facts WHERE id = ?`, hotID).Scan(&servedCount, &lastServed); err != nil {
		t.Fatalf("query hotID served_count: %v", err)
	}
	if servedCount != expectedHits || !lastServed.Valid {
		t.Fatalf("expected hotID served_count=%d with non-null last_served_at, got count=%d last_served=%+v", expectedHits, servedCount, lastServed)
	}

	// 4. Stress concurrent MutatePreMask racing directly against Close() with tiny queue size (drop path + race safety).
	tinyPlugin, err := memory.NewPlugin(memory.Options{
		SQLitePath:         dbPath,
		HitQueueSize:       2,
		HitFlushIntervalMs: 500,
	})
	if err != nil {
		t.Fatalf("NewPlugin tinyQueue: %v", err)
	}
	var raceWG sync.WaitGroup
	for g := 0; g < 12; g++ {
		raceWG.Add(1)
		go func() {
			defer raceWG.Done()
			for i := 0; i < 20; i++ {
				req, _ := proxy.ParseRequest([]byte(`{"model":"default","messages":[{"role":"user","content":"核心路由策略说明"}]}`))
				_ = tinyPlugin.MutatePreMask(ctx, req, &proxy.RequestMeta{ClientName: "alice", Values: map[string]any{}})
			}
		}()
	}
	time.Sleep(5 * time.Millisecond)
	_ = tinyPlugin.Close()
	raceWG.Wait()
}
