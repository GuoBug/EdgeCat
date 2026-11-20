// Package memory implements EdgeCat's opt-in layered memory RequestMutator plugin (R3.2).
//
// Architecture invariants:
//  1. Dual SQLite handles: a single-connection Writer (MaxOpenConns=1) and a
//     separate read-only Reader pool (query_only=ON) so hot-path retrieval never
//     blocks behind writes.
//  2. CJK-capable FTS5 full-text search using the built-in SQLite trigram tokenizer
//     (pure Go modernc.org/sqlite, preserving CGO_ENABLED=0).
//  3. Layered storage & namespace isolation: long-term distilled non-PII facts
//     plus TTL-bounded short-term summaries, strictly partitioned by client_name.
//     Any PII encountered before persistence is redacted via HMAC-SHA256 stable
//     keys when configured (or request-local placeholders), never stored in plaintext.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package memory

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"

	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/proxy"
)

// Options configures the opt-in layered memory plugin.
type Options struct {
	SQLitePath         string
	MaxFacts           int
	MaxShortTerm       int
	QueryTimeoutMs     int
	ReaderMaxOpenConns int
	Masker             *filter.Masker
	HMACSecret         []byte
}

// Fact represents a distilled, non-PII long-term memory entry scoped to a client.
type Fact struct {
	ID         int64
	ClientName string
	Fact       string
	Tags       string
	CreatedAt  time.Time
}

// ShortTermEntry represents a TTL-bounded recent context summary scoped to a client.
type ShortTermEntry struct {
	ID         int64
	ClientName string
	Summary    string
	ExpiresAt  time.Time
}

// Plugin is a dual-handle SQLite FTS5 layered memory plugin implementing proxy.RequestMutator.
type Plugin struct {
	writerDB     *sql.DB
	readerDB     *sql.DB
	maxFacts     int
	maxShortTerm int
	queryTimeout time.Duration
	masker       *filter.Masker
	hmacSecret   []byte
}

// NewPlugin initializes separate Writer (MaxOpenConns=1) and Reader SQLite pools
// and prepares the trigram FTS5 schema.
func NewPlugin(opts Options) (*Plugin, error) {
	if opts.SQLitePath == "" {
		opts.SQLitePath = "data/edgecat_memory.db"
	}
	if opts.MaxFacts <= 0 {
		opts.MaxFacts = 5
	}
	if opts.MaxShortTerm <= 0 {
		opts.MaxShortTerm = 3
	}
	if opts.QueryTimeoutMs <= 0 {
		opts.QueryTimeoutMs = 50
	}
	if opts.ReaderMaxOpenConns <= 0 {
		opts.ReaderMaxOpenConns = 4
	}

	dir := filepath.Dir(opts.SQLitePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create memory db directory: %w", err)
		}
	}

	writerDSN := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)", opts.SQLitePath)
	writerDB, err := sql.Open("sqlite", writerDSN)
	if err != nil {
		return nil, fmt.Errorf("open memory writer db: %w", err)
	}
	writerDB.SetMaxOpenConns(1)
	writerDB.SetMaxIdleConns(1)

	if err := initMemorySchema(writerDB); err != nil {
		_ = writerDB.Close()
		return nil, fmt.Errorf("init memory schema: %w", err)
	}

	readerDSN := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=query_only(ON)&_pragma=busy_timeout(5000)", opts.SQLitePath)
	readerDB, err := sql.Open("sqlite", readerDSN)
	if err != nil {
		_ = writerDB.Close()
		return nil, fmt.Errorf("open memory reader db: %w", err)
	}
	readerDB.SetMaxOpenConns(opts.ReaderMaxOpenConns)
	readerDB.SetMaxIdleConns(opts.ReaderMaxOpenConns)

	var secretCopy []byte
	if len(opts.HMACSecret) > 0 {
		secretCopy = make([]byte, len(opts.HMACSecret))
		copy(secretCopy, opts.HMACSecret)
	}

	return &Plugin{
		writerDB:     writerDB,
		readerDB:     readerDB,
		maxFacts:     opts.MaxFacts,
		maxShortTerm: opts.MaxShortTerm,
		queryTimeout: time.Duration(opts.QueryTimeoutMs) * time.Millisecond,
		masker:       opts.Masker,
		hmacSecret:   secretCopy,
	}, nil
}

func initMemorySchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS memory_facts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_name TEXT NOT NULL,
		fact TEXT NOT NULL,
		tags TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_memory_facts_client ON memory_facts(client_name);

	CREATE VIRTUAL TABLE IF NOT EXISTS memory_facts_fts USING fts5(
		fact,
		tags,
		content='memory_facts',
		content_rowid='id',
		tokenize='trigram'
	);

	CREATE TRIGGER IF NOT EXISTS memory_facts_ai AFTER INSERT ON memory_facts BEGIN
		INSERT INTO memory_facts_fts(rowid, fact, tags) VALUES (new.id, new.fact, new.tags);
	END;
	CREATE TRIGGER IF NOT EXISTS memory_facts_ad AFTER DELETE ON memory_facts BEGIN
		INSERT INTO memory_facts_fts(memory_facts_fts, rowid, fact, tags) VALUES ('delete', old.id, old.fact, old.tags);
	END;
	CREATE TRIGGER IF NOT EXISTS memory_facts_au AFTER UPDATE ON memory_facts BEGIN
		INSERT INTO memory_facts_fts(memory_facts_fts, rowid, fact, tags) VALUES ('delete', old.id, old.fact, old.tags);
		INSERT INTO memory_facts_fts(rowid, fact, tags) VALUES (new.id, new.fact, new.tags);
	END;

	CREATE TABLE IF NOT EXISTS memory_short_term (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_name TEXT NOT NULL,
		summary TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_memory_short_term_client_exp ON memory_short_term(client_name, expires_at);
	`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	return nil
}

// Close releases both the Reader and Writer SQLite pools.
func (p *Plugin) Close() error {
	var firstErr error
	if p.readerDB != nil {
		if err := p.readerDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if p.writerDB != nil {
		if err := p.writerDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Name implements proxy.RequestMutator.
func (p *Plugin) Name() string {
	return "layered_memory"
}

// MutatePreMask implements proxy.RequestMutator (Stage 1: before PII masking).
// It retrieves client-isolated long-term facts and unexpired short-term summaries
// via the read-only pool within a bounded timeout and prepends them as system context.
func (p *Plugin) MutatePreMask(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
	if req == nil || meta == nil {
		return nil
	}

	query := latestUserQuery(req)
	qCtx, cancel := context.WithTimeout(ctx, p.queryTimeout)
	defer cancel()

	clientName := normalizeClient(meta.ClientName)

	var facts []Fact
	var err error
	if query != "" {
		facts, err = p.SearchFacts(qCtx, clientName, query, p.maxFacts)
		if err != nil {
			log.Printf("[Memory] Fact lookup skipped for client=%q: %v", clientName, err)
			facts = nil
		}
	}

	shortTerm, err := p.ListShortTerm(qCtx, clientName, p.maxShortTerm)
	if err != nil {
		log.Printf("[Memory] Short-term lookup skipped for client=%q: %v", clientName, err)
		shortTerm = nil
	}

	if len(facts) == 0 && len(shortTerm) == 0 {
		return nil
	}

	var b strings.Builder
	b.WriteString("[EdgeCat Memory Context]\n")
	if len(facts) > 0 {
		b.WriteString("Long-term facts:\n")
		for _, f := range facts {
			b.WriteString("- ")
			b.WriteString(f.Fact)
			b.WriteString("\n")
		}
	}
	if len(shortTerm) > 0 {
		b.WriteString("Recent context:\n")
		for _, s := range shortTerm {
			b.WriteString("- ")
			b.WriteString(s.Summary)
			b.WriteString("\n")
		}
	}

	req.PrependSystemMessage(strings.TrimSpace(b.String()))
	if meta.Values != nil {
		meta.Values["memory_facts_injected"] = len(facts)
		meta.Values["memory_short_term_injected"] = len(shortTerm)
	}
	return nil
}

// MutatePostMask implements proxy.RequestMutator (Stage 2: no-op for memory injection).
func (p *Plugin) MutatePostMask(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
	return nil
}

// AddFact persists a distilled long-term fact scoped to clientName via the single-connection Writer.
// If a PII Masker is configured, any detected PII is redacted (using HMAC-SHA256 stable keys
// when HMACSecret is set) before touching disk.
func (p *Plugin) AddFact(ctx context.Context, clientName, fact, tags string) (int64, error) {
	clientName = normalizeClient(clientName)
	fact = strings.TrimSpace(p.sanitizeForStorage(fact))
	tags = strings.TrimSpace(p.sanitizeForStorage(tags))
	if fact == "" {
		return 0, fmt.Errorf("fact must not be empty")
	}

	res, err := p.writerDB.ExecContext(ctx,
		`INSERT INTO memory_facts (client_name, fact, tags) VALUES (?, ?, ?)`,
		clientName, fact, tags,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// AddShortTerm persists a TTL-bounded short-term summary scoped to clientName.
func (p *Plugin) AddShortTerm(ctx context.Context, clientName, summary string, ttl time.Duration) (int64, error) {
	clientName = normalizeClient(clientName)
	summary = strings.TrimSpace(p.sanitizeForStorage(summary))
	if summary == "" {
		return 0, fmt.Errorf("summary must not be empty")
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	expiresAt := time.Now().Add(ttl).Unix()

	res, err := p.writerDB.ExecContext(ctx,
		`INSERT INTO memory_short_term (client_name, summary, expires_at) VALUES (?, ?, ?)`,
		clientName, summary, expiresAt,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// PurgeExpired removes expired short-term memory records using the Writer handle.
func (p *Plugin) PurgeExpired(ctx context.Context) (int64, error) {
	res, err := p.writerDB.ExecContext(ctx,
		`DELETE FROM memory_short_term WHERE expires_at <= ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SearchFacts queries the read-only Reader pool using FTS5 trigram matching
// (with a safe LIKE fallback for short <3-rune queries), strictly isolated by clientName.
func (p *Plugin) SearchFacts(ctx context.Context, clientName, query string, limit int) ([]Fact, error) {
	clientName = normalizeClient(clientName)
	if limit <= 0 {
		limit = p.maxFacts
	}

	ftsExpr := buildTrigramFTSQuery(query)
	if ftsExpr != "" {
		rows, err := p.readerDB.QueryContext(ctx, `
			SELECT f.id, f.client_name, f.fact, f.tags, f.created_at
			FROM memory_facts_fts fts
			JOIN memory_facts f ON f.id = fts.rowid
			WHERE memory_facts_fts MATCH ? AND f.client_name = ?
			ORDER BY bm25(memory_facts_fts), f.id DESC
			LIMIT ?
		`, ftsExpr, clientName, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		facts, err := scanFacts(rows)
		if err != nil {
			return nil, err
		}
		if len(facts) > 0 {
			return facts, nil
		}
	}

	// Fallback for short queries (< 3 runes) where SQLite trigram cannot index tokens.
	trimmed := strings.TrimSpace(query)
	if trimmed == "" || utf8.RuneCountInString(trimmed) >= 3 {
		return nil, nil
	}
	pattern := "%" + trimmed + "%"
	rows, err := p.readerDB.QueryContext(ctx, `
		SELECT id, client_name, fact, tags, created_at
		FROM memory_facts
		WHERE client_name = ? AND (fact LIKE ? OR tags LIKE ?)
		ORDER BY id DESC
		LIMIT ?
	`, clientName, pattern, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFacts(rows)
}

// ListShortTerm returns unexpired short-term summaries for clientName via the Reader pool.
func (p *Plugin) ListShortTerm(ctx context.Context, clientName string, limit int) ([]ShortTermEntry, error) {
	clientName = normalizeClient(clientName)
	if limit <= 0 {
		limit = p.maxShortTerm
	}

	rows, err := p.readerDB.QueryContext(ctx, `
		SELECT id, client_name, summary, expires_at
		FROM memory_short_term
		WHERE client_name = ? AND expires_at > ?
		ORDER BY id DESC
		LIMIT ?
	`, clientName, time.Now().Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []ShortTermEntry
	for rows.Next() {
		var e ShortTermEntry
		var expUnix int64
		if err := rows.Scan(&e.ID, &e.ClientName, &e.Summary, &expUnix); err != nil {
			return nil, err
		}
		e.ExpiresAt = time.Unix(expUnix, 0)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ReaderMaxOpenConns returns the configured Reader pool cap (useful for diagnostics/tests).
func (p *Plugin) ReaderMaxOpenConns() int {
	if p.readerDB == nil {
		return 0
	}
	return p.readerDB.Stats().MaxOpenConnections
}

// WriterMaxOpenConns returns the configured Writer pool cap (always 1).
func (p *Plugin) WriterMaxOpenConns() int {
	if p.writerDB == nil {
		return 0
	}
	return p.writerDB.Stats().MaxOpenConnections
}

func (p *Plugin) sanitizeForStorage(text string) string {
	if p.masker == nil || text == "" {
		return text
	}
	var vault *filter.Vault
	if len(p.hmacSecret) > 0 {
		vault = filter.NewStableVault(p.hmacSecret)
	} else {
		vault = filter.NewVault()
	}
	return p.masker.MaskText(text, vault)
}

func normalizeClient(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "anonymous"
	}
	return name
}

func scanFacts(rows *sql.Rows) ([]Fact, error) {
	var facts []Fact
	for rows.Next() {
		var f Fact
		if err := rows.Scan(&f.ID, &f.ClientName, &f.Fact, &f.Tags, &f.CreatedAt); err != nil {
			return nil, err
		}
		facts = append(facts, f)
	}
	return facts, rows.Err()
}

// latestUserQuery extracts the textual content of the last user message.
func latestUserQuery(req *proxy.Request) string {
	msgs := req.Messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		m, ok := msgs[i].(map[string]any)
		if !ok {
			continue
		}
		if role, _ := m["role"].(string); role != "user" {
			continue
		}
		switch content := m["content"].(type) {
		case string:
			return strings.TrimSpace(content)
		case []any:
			var parts []string
			for _, rp := range content {
				part, ok := rp.(map[string]any)
				if !ok || part["type"] != "text" {
					continue
				}
				if text, ok := part["text"].(string); ok && strings.TrimSpace(text) != "" {
					parts = append(parts, strings.TrimSpace(text))
				}
			}
			return strings.Join(parts, " ")
		}
	}
	return ""
}

// buildTrigramFTSQuery converts a free-form CJK/ASCII user query into a safe,
// bounded FTS5 trigram OR expression. Every token is double-quoted so user
// punctuation never triggers FTS5 syntax errors.
func buildTrigramFTSQuery(raw string) string {
	const maxTerms = 12

	// Split on whitespace and punctuation into alphanumeric/CJK runs.
	runs := strings.FieldsFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsSymbol(r)
	})

	seen := make(map[string]struct{})
	terms := make([]string, 0, maxTerms)
	addTerm := func(tok string) {
		if len(terms) >= maxTerms || utf8.RuneCountInString(tok) < 3 {
			return
		}
		if _, exists := seen[tok]; exists {
			return
		}
		seen[tok] = struct{}{}
		escaped := strings.ReplaceAll(tok, `"`, `""`)
		terms = append(terms, `"`+escaped+`"`)
	}

	for _, run := range runs {
		runes := []rune(run)
		if len(runes) < 3 {
			continue
		}
		if containsCJK(runes) && len(runes) > 3 {
			// Emit sliding 3-rune CJK windows so continuous Chinese sentences match
			// stored facts without requiring whole-sentence substring equality.
			for i := 0; i <= len(runes)-3 && len(terms) < maxTerms; i++ {
				addTerm(string(runes[i : i+3]))
			}
		} else {
			addTerm(run)
		}
		if len(terms) >= maxTerms {
			break
		}
	}

	return strings.Join(terms, " OR ")
}

func containsCJK(runes []rune) bool {
	for _, r := range runes {
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r) {
			return true
		}
	}
	return false
}
