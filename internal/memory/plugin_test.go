// Package memory_test verifies EdgeCat's opt-in layered memory plugin (R3.2).
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package memory_test

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
