// Package memory implements EdgeCat's opt-in layered memory RequestMutator plugin (R3.2 / R3.2.1).
//
// Architecture invariants:
//  1. Dual SQLite handles: a single-connection Writer (MaxOpenConns=1) and a
//     separate read-only Reader pool (query_only=ON) so hot-path retrieval never
//     blocks behind writes.
//  2. CJK-capable FTS5 full-text search using the built-in SQLite trigram tokenizer
//     (pure Go modernc.org/sqlite, preserving CGO_ENABLED=0).
//  3. Layered storage & namespace isolation: long-term distilled non-PII facts
//     (with temporal supersede chains, dormancy governance, and pinned static rules)
//     plus TTL-bounded short-term summaries, strictly partitioned by client_name.
//     Any PII encountered before persistence is redacted via HMAC-SHA256 stable
//     keys when configured (or request-local placeholders), never stored in plaintext.
//  4. Prefix-Cache preservation: pinned facts render deterministically at messages[0]
//     (Zone 1), while dynamic search hits and short-term summaries are injected right
//     before the last user turn (Zone 2) so multi-turn KV cache prefixes stay intact.
//  5. Lock-free hit tracking: MutatePreMask never writes to SQLite synchronously;
//     served counters flow through a non-blocking bounded channel to a single
//     background writer goroutine (dropping updates if full).
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package memory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"

	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/proxy"
)

const (
	// maxSupersedeHops bounds forward lineage traversal during SearchFacts to prevent
	// infinite loops even if an external tool corrupts superseded_by into a cycle.
	maxSupersedeHops = 5

	defaultMaxPinnedFacts     = 10
	defaultMaxFacts           = 5
	defaultMaxShortTerm       = 3
	defaultQueryTimeoutMs     = 50
	defaultReaderMaxOpenConns = 4
	defaultHitQueueSize       = 256
	defaultHitFlushIntervalMs = 200
	hitFlushBatchThreshold    = 64

	// DormantReasonUnused marks facts auto-hibernated due to prolonged non-retrieval.
	DormantReasonUnused = "unused"
	// DormantReasonQuoteMissing marks facts hibernated when their source anchor disappears.
	DormantReasonQuoteMissing = "quote_missing"
)

var (
	// ErrFactNotFound indicates that no matching fact exists within the caller's client_name namespace.
	ErrFactNotFound = errors.New("memory fact not found for client")
	// ErrFactConflict indicates that a fact has already been superseded or invalidated.
	ErrFactConflict = errors.New("memory fact already superseded or invalidated")
)

// Options configures the opt-in layered memory plugin.
type Options struct {
	SQLitePath            string
	MaxPinnedFacts        int
	MaxFacts              int
	MaxShortTerm          int
	QueryTimeoutMs        int
	ReaderMaxOpenConns    int
	PrependDynamicContext bool
	HitQueueSize          int
	HitFlushIntervalMs    int
	Masker                *filter.Masker
	HMACSecret            []byte
}

// FactMeta carries optional governance attributes when persisting a long-term fact.
type FactMeta struct {
	Tags        string
	Pinned      bool
	SourceQuote string
}

// Fact represents a distilled, non-PII long-term memory entry scoped to a client.
type Fact struct {
	ID            int64
	ClientName    string
	Fact          string
	Tags          string
	Pinned        bool
	ValidTo       *time.Time
	SupersededBy  *int64
	DormantReason string
	SourceQuote   string
	LastServedAt  *time.Time
	ServedCount   int64
	CreatedAt     time.Time
}

// ShortTermEntry represents a TTL-bounded recent context summary scoped to a client.
type ShortTermEntry struct {
	ID         int64
	ClientName string
	Summary    string
	ExpiresAt  time.Time
}

type servedHitEvent struct {
	clientName string
	factIDs    []int64
	servedUnix int64
}

type hitKey struct {
	clientName string
	factID     int64
}

type hitDelta struct {
	count      int64
	lastServed int64
}

// Plugin is a dual-handle SQLite FTS5 layered memory plugin implementing proxy.RequestMutator.
type Plugin struct {
	writerDB              *sql.DB
	readerDB              *sql.DB
	maxPinnedFacts        int
	maxFacts              int
	maxShortTerm          int
	queryTimeout          time.Duration
	prependDynamicContext bool
	masker                *filter.Masker
	hmacSecret            []byte

	hitCh         chan servedHitEvent
	hitFlushEvery time.Duration
	stopCh        chan struct{}
	wg            sync.WaitGroup
	closeOnce     sync.Once
	closeErr      error
	closed        atomic.Bool
	droppedHits   atomic.Int64
	flushedHits   atomic.Int64
}

// NewPlugin initializes separate Writer (MaxOpenConns=1) and Reader SQLite pools,
// performs idempotent schema evolution, and starts the background hit tracker.
func NewPlugin(opts Options) (*Plugin, error) {
	if opts.SQLitePath == "" {
		opts.SQLitePath = "data/edgecat_memory.db"
	}
	if opts.MaxPinnedFacts <= 0 {
		opts.MaxPinnedFacts = defaultMaxPinnedFacts
	}
	if opts.MaxFacts <= 0 {
		opts.MaxFacts = defaultMaxFacts
	}
	if opts.MaxShortTerm <= 0 {
		opts.MaxShortTerm = defaultMaxShortTerm
	}
	if opts.QueryTimeoutMs <= 0 {
		opts.QueryTimeoutMs = defaultQueryTimeoutMs
	}
	if opts.ReaderMaxOpenConns <= 0 {
		opts.ReaderMaxOpenConns = defaultReaderMaxOpenConns
	}
	if opts.HitQueueSize <= 0 {
		opts.HitQueueSize = defaultHitQueueSize
	}
	if opts.HitFlushIntervalMs <= 0 {
		opts.HitFlushIntervalMs = defaultHitFlushIntervalMs
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

	p := &Plugin{
		writerDB:              writerDB,
		readerDB:              readerDB,
		maxPinnedFacts:        opts.MaxPinnedFacts,
		maxFacts:              opts.MaxFacts,
		maxShortTerm:          opts.MaxShortTerm,
		queryTimeout:          time.Duration(opts.QueryTimeoutMs) * time.Millisecond,
		prependDynamicContext: opts.PrependDynamicContext,
		masker:                opts.Masker,
		hmacSecret:            secretCopy,
		hitCh:                 make(chan servedHitEvent, opts.HitQueueSize),
		hitFlushEvery:         time.Duration(opts.HitFlushIntervalMs) * time.Millisecond,
		stopCh:                make(chan struct{}),
	}

	p.wg.Add(1)
	go p.hitWorker()

	return p, nil
}

func initMemorySchema(db *sql.DB) error {
	var ftsExisted int
	_ = db.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = 'memory_facts_fts'`).Scan(&ftsExisted)

	baseSchema := `
	CREATE TABLE IF NOT EXISTS memory_facts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_name TEXT NOT NULL,
		fact TEXT NOT NULL,
		tags TEXT NOT NULL DEFAULT '',
		pinned INTEGER NOT NULL DEFAULT 0,
		valid_to INTEGER DEFAULT NULL,
		superseded_by INTEGER DEFAULT NULL,
		dormant_reason TEXT NOT NULL DEFAULT '',
		source_quote TEXT NOT NULL DEFAULT '',
		last_served_at INTEGER DEFAULT NULL,
		served_count INTEGER NOT NULL DEFAULT 0,
		created_at_unix INTEGER DEFAULT NULL,
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

	-- Scope the UPDATE trigger to text columns (fact, tags) so background hit
	-- counter flushes and dormancy state transitions never re-tokenize FTS5.
	DROP TRIGGER IF EXISTS memory_facts_au;
	CREATE TRIGGER memory_facts_au AFTER UPDATE OF fact, tags ON memory_facts BEGIN
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
	if _, err := db.Exec(baseSchema); err != nil {
		return err
	}

	if err := migrateMemoryFactsColumns(db); err != nil {
		return err
	}

	postMigrationSchema := `
	CREATE INDEX IF NOT EXISTS idx_memory_facts_client_pinned
		ON memory_facts(client_name, pinned, id);
	CREATE INDEX IF NOT EXISTS idx_memory_facts_client_active
		ON memory_facts(client_name, valid_to, superseded_by, dormant_reason);
	`
	if _, err := db.Exec(postMigrationSchema); err != nil {
		return err
	}

	if ftsExisted == 0 {
		var existingRows int
		if err := db.QueryRow(`SELECT COUNT(1) FROM memory_facts`).Scan(&existingRows); err == nil && existingRows > 0 {
			if _, err := db.Exec(`INSERT INTO memory_facts_fts(memory_facts_fts) VALUES('rebuild')`); err != nil {
				return fmt.Errorf("rebuild memory_facts_fts for legacy rows: %w", err)
			}
		}
	}

	return nil
}

// migrateMemoryFactsColumns inspects PRAGMA table_info(memory_facts) and applies
// idempotent ALTER TABLE ADD COLUMN migrations for pre-R3.2.1 databases.
func migrateMemoryFactsColumns(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(memory_facts)`)
	if err != nil {
		return fmt.Errorf("pragma table_info(memory_facts): %w", err)
	}
	existing := make(map[string]bool)
	for rows.Next() {
		var (
			cid       int
			name      string
			colType   sql.NullString
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan pragma table_info(memory_facts): %w", err)
		}
		existing[strings.ToLower(name)] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	migrations := []struct {
		column string
		ddl    string
	}{
		{"pinned", `ALTER TABLE memory_facts ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0`},
		{"valid_to", `ALTER TABLE memory_facts ADD COLUMN valid_to INTEGER DEFAULT NULL`},
		{"superseded_by", `ALTER TABLE memory_facts ADD COLUMN superseded_by INTEGER DEFAULT NULL`},
		{"dormant_reason", `ALTER TABLE memory_facts ADD COLUMN dormant_reason TEXT NOT NULL DEFAULT ''`},
		{"source_quote", `ALTER TABLE memory_facts ADD COLUMN source_quote TEXT NOT NULL DEFAULT ''`},
		{"last_served_at", `ALTER TABLE memory_facts ADD COLUMN last_served_at INTEGER DEFAULT NULL`},
		{"served_count", `ALTER TABLE memory_facts ADD COLUMN served_count INTEGER NOT NULL DEFAULT 0`},
		{"created_at_unix", `ALTER TABLE memory_facts ADD COLUMN created_at_unix INTEGER DEFAULT NULL`},
	}

	for _, m := range migrations {
		if existing[m.column] {
			continue
		}
		if _, err := db.Exec(m.ddl); err != nil {
			return fmt.Errorf("migrate memory_facts.%s: %w", m.column, err)
		}
	}

	if _, err := db.Exec(`
		UPDATE memory_facts
		SET created_at_unix = COALESCE(CAST(strftime('%s', created_at) AS INTEGER), 0)
		WHERE created_at_unix IS NULL
	`); err != nil {
		return fmt.Errorf("backfill memory_facts.created_at_unix: %w", err)
	}

	return nil
}

// Close drains queued hit counter updates and releases both Reader and Writer SQLite pools.
// Safe for concurrent and repeated invocation.
func (p *Plugin) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		close(p.stopCh)
		p.wg.Wait()

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
		p.closeErr = firstErr
	})
	return p.closeErr
}

// Name implements proxy.RequestMutator.
func (p *Plugin) Name() string {
	return "layered_memory"
}

// MutatePreMask implements proxy.RequestMutator (Stage 1: before PII masking).
//
// R3.2.1 Two-Zone Injection:
//   - Zone 1 (Static Prefix): pinned=1 active facts sorted strictly by id ASC,
//     prepended at messages[0] as "[EdgeCat Pinned Rules]" for byte-deterministic
//     KV / Prefix Cache hits across multi-turn chats.
//   - Zone 2 (Dynamic Tail): query-dependent SearchFacts + unexpired ListShortTerm,
//     inserted as "[EdgeCat Dynamic Context]" immediately before the last user
//     message (or prepended after Zone 1 if PrependDynamicContext is enabled).
func (p *Plugin) MutatePreMask(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
	if req == nil || meta == nil || p.closed.Load() {
		return nil
	}

	query := latestUserQuery(req)
	qCtx, cancel := context.WithTimeout(ctx, p.queryTimeout)
	defer cancel()

	clientName := normalizeClient(meta.ClientName)

	pinnedFacts, err := p.ListPinnedFacts(qCtx, clientName, p.maxPinnedFacts)
	if err != nil {
		log.Printf("[Memory] Pinned fact lookup skipped for client=%q: %v", clientName, err)
		pinnedFacts = nil
	}

	var facts []Fact
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

	if meta.Values != nil {
		meta.Values["memory_pinned_injected"] = len(pinnedFacts)
		meta.Values["memory_facts_injected"] = len(facts)
		meta.Values["memory_short_term_injected"] = len(shortTerm)
	}

	if len(pinnedFacts) == 0 && len(facts) == 0 && len(shortTerm) == 0 {
		return nil
	}

	zone1 := renderPinnedZone(pinnedFacts)
	zone2 := renderDynamicZone(facts, shortTerm)

	if p.prependDynamicContext {
		// Compatibility fallback for strict non-standard chat templates that reject
		// mid-conversation system messages. Prepend Zone 2 first so Zone 1 still sits at messages[0].
		if zone2 != "" {
			req.PrependSystemMessage(zone2)
		}
		if zone1 != "" {
			req.PrependSystemMessage(zone1)
		}
	} else {
		if zone1 != "" {
			req.PrependSystemMessage(zone1)
		}
		if zone2 != "" {
			req.InsertSystemBeforeLastUser(zone2)
		}
	}

	p.enqueueServedFacts(clientName, pinnedFacts, facts)
	return nil
}

func renderPinnedZone(pinned []Fact) string {
	if len(pinned) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("[EdgeCat Pinned Rules]")
	for _, f := range pinned {
		b.WriteString("\n- ")
		b.WriteString(f.Fact)
	}
	return b.String()
}

func renderDynamicZone(facts []Fact, shortTerm []ShortTermEntry) string {
	if len(facts) == 0 && len(shortTerm) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("[EdgeCat Dynamic Context]")
	if len(facts) > 0 {
		b.WriteString("\nLong-term facts:")
		for _, f := range facts {
			b.WriteString("\n- ")
			b.WriteString(f.Fact)
		}
	}
	if len(shortTerm) > 0 {
		b.WriteString("\nRecent context:")
		for _, s := range shortTerm {
			b.WriteString("\n- ")
			b.WriteString(s.Summary)
		}
	}
	return b.String()
}

// MutatePostMask implements proxy.RequestMutator (Stage 2: no-op for memory injection).
func (p *Plugin) MutatePostMask(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
	return nil
}

// AddFact persists a distilled long-term fact scoped to clientName via the single-connection Writer.
// If an active, non-superseded fact with identical sanitized text already exists for clientName,
// AddFact returns the existing ID idempotently (waking it if dormant).
func (p *Plugin) AddFact(ctx context.Context, clientName, fact, tags string) (int64, error) {
	return p.AddFactWithMeta(ctx, clientName, fact, FactMeta{Tags: tags})
}

// AddFactWithMeta persists a distilled long-term fact with optional Pinned and SourceQuote
// attributes. All text fields (fact, tags, source_quote) are sanitized through the PII Masker
// before touching SQLite. Duplicate active facts under the same clientName are deduplicated
// idempotently, promoting pinned=1 or waking dormant entries when applicable.
func (p *Plugin) AddFactWithMeta(ctx context.Context, clientName, fact string, meta FactMeta) (int64, error) {
	clientName = normalizeClient(clientName)
	cleanFact := strings.TrimSpace(p.sanitizeForStorage(fact))
	cleanTags := strings.TrimSpace(p.sanitizeForStorage(meta.Tags))
	cleanQuote := strings.TrimSpace(p.sanitizeForStorage(meta.SourceQuote))
	if cleanFact == "" {
		return 0, fmt.Errorf("fact must not be empty")
	}

	nowUnix := time.Now().Unix()

	tx, err := p.writerDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		existingID      int64
		existingPinned  int
		existingDormant string
		existingTags    string
		existingQuote   string
	)
	err = tx.QueryRowContext(ctx, `
		SELECT id, pinned, dormant_reason, tags, source_quote
		FROM memory_facts
		WHERE client_name = ? AND fact = ? AND valid_to IS NULL AND superseded_by IS NULL
		ORDER BY id DESC
		LIMIT 1
	`, clientName, cleanFact).Scan(&existingID, &existingPinned, &existingDormant, &existingTags, &existingQuote)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	if err == nil {
		newPinned := existingPinned
		if meta.Pinned && existingPinned == 0 {
			newPinned = 1
		}
		newDormant := existingDormant
		touchServed := false
		if existingDormant != "" {
			newDormant = ""
			touchServed = true
		}
		newTags := existingTags
		if cleanTags != "" && existingTags == "" {
			newTags = cleanTags
		}
		newQuote := existingQuote
		if cleanQuote != "" && cleanQuote != existingQuote {
			newQuote = cleanQuote
		}

		if newPinned != existingPinned || newDormant != existingDormant || newTags != existingTags || newQuote != existingQuote {
			if touchServed {
				if _, err := tx.ExecContext(ctx, `
					UPDATE memory_facts
					SET pinned = ?, dormant_reason = ?, tags = ?, source_quote = ?, last_served_at = ?, updated_at = CURRENT_TIMESTAMP
					WHERE id = ? AND client_name = ?
				`, newPinned, newDormant, newTags, newQuote, nowUnix, existingID, clientName); err != nil {
					return 0, err
				}
			} else {
				if _, err := tx.ExecContext(ctx, `
					UPDATE memory_facts
					SET pinned = ?, dormant_reason = ?, tags = ?, source_quote = ?, updated_at = CURRENT_TIMESTAMP
					WHERE id = ? AND client_name = ?
				`, newPinned, newDormant, newTags, newQuote, existingID, clientName); err != nil {
					return 0, err
				}
			}
		}

		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return existingID, nil
	}

	pinnedInt := 0
	if meta.Pinned {
		pinnedInt = 1
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO memory_facts (client_name, fact, tags, pinned, source_quote, created_at_unix)
		VALUES (?, ?, ?, ?, ?, ?)
	`, clientName, cleanFact, cleanTags, pinnedInt, cleanQuote, nowUnix)
	if err != nil {
		return 0, err
	}
	newID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return newID, nil
}

// SupersedeFact atomically replaces oldID with newFact inside a single writerDB transaction.
// Returns ErrFactNotFound if oldID does not exist under clientName (preventing cross-client
// tampering) and ErrFactConflict if oldID was already superseded or invalidated (preventing
// forked temporal chains). Inherits the pinned flag of oldID.
func (p *Plugin) SupersedeFact(ctx context.Context, clientName string, oldID int64, newFact, tags string) (int64, error) {
	return p.supersedeFactInternal(ctx, clientName, oldID, newFact, FactMeta{Tags: tags}, true)
}

// SupersedeFactWithMeta atomically supersedes oldID with explicit FactMeta (Tags, Pinned, SourceQuote).
func (p *Plugin) SupersedeFactWithMeta(ctx context.Context, clientName string, oldID int64, newFact string, meta FactMeta) (int64, error) {
	return p.supersedeFactInternal(ctx, clientName, oldID, newFact, meta, false)
}

func (p *Plugin) supersedeFactInternal(ctx context.Context, clientName string, oldID int64, newFact string, meta FactMeta, inheritPinned bool) (int64, error) {
	clientName = normalizeClient(clientName)
	if oldID <= 0 {
		return 0, fmt.Errorf("%w: invalid id %d", ErrFactNotFound, oldID)
	}
	cleanFact := strings.TrimSpace(p.sanitizeForStorage(newFact))
	cleanTags := strings.TrimSpace(p.sanitizeForStorage(meta.Tags))
	cleanQuote := strings.TrimSpace(p.sanitizeForStorage(meta.SourceQuote))
	if cleanFact == "" {
		return 0, fmt.Errorf("new fact must not be empty")
	}

	nowUnix := time.Now().Unix()

	tx, err := p.writerDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		validTo      sql.NullInt64
		supersededBy sql.NullInt64
		oldPinned    int
	)
	err = tx.QueryRowContext(ctx, `
		SELECT valid_to, superseded_by, pinned
		FROM memory_facts
		WHERE id = ? AND client_name = ?
	`, oldID, clientName).Scan(&validTo, &supersededBy, &oldPinned)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: id=%d client=%s", ErrFactNotFound, oldID, clientName)
	}
	if err != nil {
		return 0, err
	}
	if validTo.Valid || supersededBy.Valid {
		return 0, fmt.Errorf("%w: id=%d", ErrFactConflict, oldID)
	}

	pinnedInt := 0
	if inheritPinned {
		pinnedInt = oldPinned
	} else if meta.Pinned {
		pinnedInt = 1
	}

	insRes, err := tx.ExecContext(ctx, `
		INSERT INTO memory_facts (client_name, fact, tags, pinned, source_quote, created_at_unix)
		VALUES (?, ?, ?, ?, ?, ?)
	`, clientName, cleanFact, cleanTags, pinnedInt, cleanQuote, nowUnix)
	if err != nil {
		return 0, err
	}
	newID, err := insRes.LastInsertId()
	if err != nil {
		return 0, err
	}

	updRes, err := tx.ExecContext(ctx, `
		UPDATE memory_facts
		SET valid_to = ?, superseded_by = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND client_name = ? AND valid_to IS NULL AND superseded_by IS NULL
	`, nowUnix, newID, oldID, clientName)
	if err != nil {
		return 0, err
	}
	affected, err := updRes.RowsAffected()
	if err != nil {
		return 0, err
	}
	if affected != 1 {
		return 0, fmt.Errorf("%w: id=%d", ErrFactConflict, oldID)
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return newID, nil
}

// GetFact retrieves a single fact strictly scoped to clientName via the read-only pool.
func (p *Plugin) GetFact(ctx context.Context, clientName string, factID int64) (*Fact, error) {
	clientName = normalizeClient(clientName)
	f, err := p.queryFactByID(ctx, clientName, factID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: id=%d client=%s", ErrFactNotFound, factID, clientName)
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// ListPinnedFacts returns active, non-superseded, non-dormant pinned=1 facts for clientName
// ordered strictly by id ASC so Zone 1 prefix output is 100% byte-deterministic.
func (p *Plugin) ListPinnedFacts(ctx context.Context, clientName string, limit int) ([]Fact, error) {
	clientName = normalizeClient(clientName)
	if limit <= 0 {
		limit = p.maxPinnedFacts
	}

	rows, err := p.readerDB.QueryContext(ctx, `
		SELECT id, client_name, fact, tags, pinned, valid_to, superseded_by,
		       dormant_reason, source_quote, last_served_at, served_count, created_at
		FROM memory_facts
		WHERE client_name = ?
		  AND pinned = 1
		  AND valid_to IS NULL
		  AND superseded_by IS NULL
		  AND dormant_reason = ''
		ORDER BY id ASC
		LIMIT ?
	`, clientName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFacts(rows)
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

// SweepDormantUnused marks unpinned (pinned=0), currently active facts across each client
// namespace as dormant_reason='unused' when COALESCE(last_served_at, created_at_unix) is
// older than maxIdle. Pinned facts are never swept.
func (p *Plugin) SweepDormantUnused(ctx context.Context, maxIdle time.Duration) (int64, error) {
	if maxIdle < 0 {
		return 0, fmt.Errorf("maxIdle must be non-negative")
	}
	cutoff := time.Now().Add(-maxIdle).Unix()

	tx, err := p.writerDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT client_name FROM memory_facts WHERE pinned = 0 AND dormant_reason = '' AND valid_to IS NULL AND superseded_by IS NULL`)
	if err != nil {
		return 0, err
	}
	var clients []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			_ = rows.Close()
			return 0, err
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()

	var total int64
	for _, c := range clients {
		res, err := tx.ExecContext(ctx, `
			UPDATE memory_facts
			SET dormant_reason = ?, updated_at = CURRENT_TIMESTAMP
			WHERE client_name = ?
			  AND pinned = 0
			  AND valid_to IS NULL
			  AND superseded_by IS NULL
			  AND dormant_reason = ''
			  AND COALESCE(last_served_at, created_at_unix, CAST(strftime('%s', created_at) AS INTEGER), 0) <= ?
		`, DormantReasonUnused, c, cutoff)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		total += n
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

// MarkQuoteMissing marks an unpinned (pinned=0) fact belonging to clientName with
// dormant_reason='quote_missing'. Returns ErrFactNotFound if factID does not belong
// to clientName; pinned=1 facts belonging to clientName remain untouched (no-op).
func (p *Plugin) MarkQuoteMissing(ctx context.Context, clientName string, factID int64) error {
	clientName = normalizeClient(clientName)
	if factID <= 0 {
		return fmt.Errorf("%w: invalid id %d", ErrFactNotFound, factID)
	}

	tx, err := p.writerDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var pinned int
	err = tx.QueryRowContext(ctx, `
		SELECT pinned FROM memory_facts WHERE id = ? AND client_name = ?
	`, factID, clientName).Scan(&pinned)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: id=%d client=%s", ErrFactNotFound, factID, clientName)
	}
	if err != nil {
		return err
	}
	if pinned != 0 {
		return nil
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE memory_facts
		SET dormant_reason = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND client_name = ? AND pinned = 0
	`, DormantReasonQuoteMissing, factID, clientName); err != nil {
		return err
	}
	return tx.Commit()
}

// WakeFact clears dormant_reason='' and refreshes last_served_at for a fact belonging
// to clientName. Returns ErrFactNotFound if factID does not exist under clientName.
func (p *Plugin) WakeFact(ctx context.Context, clientName string, factID int64) error {
	clientName = normalizeClient(clientName)
	if factID <= 0 {
		return fmt.Errorf("%w: invalid id %d", ErrFactNotFound, factID)
	}

	res, err := p.writerDB.ExecContext(ctx, `
		UPDATE memory_facts
		SET dormant_reason = '', last_served_at = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND client_name = ?
	`, time.Now().Unix(), factID, clientName)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("%w: id=%d client=%s", ErrFactNotFound, factID, clientName)
	}
	return nil
}

// SearchFacts queries the read-only Reader pool using FTS5 trigram matching
// (with a safe LIKE fallback for short <3-rune queries), strictly isolated by clientName.
//
// Only currently active, non-dormant, unpinned (pinned=0) facts are returned so Zone 2
// never duplicates Zone 1 static rules. If a user query lexically matches a historical
// superseded fact (superseded_by IS NOT NULL), SearchFacts follows the superseded_by
// chain up to 5 hops (with cycle detection and strict client_name verification) and
// returns the latest active successor deduplicated by ID.
func (p *Plugin) SearchFacts(ctx context.Context, clientName, query string, limit int) ([]Fact, error) {
	clientName = normalizeClient(clientName)
	if limit <= 0 {
		limit = p.maxFacts
	}
	candidateLimit := limit * 4
	if candidateLimit < 20 {
		candidateLimit = 20
	}

	ftsExpr := buildTrigramFTSQuery(query)
	if ftsExpr != "" {
		rows, err := p.readerDB.QueryContext(ctx, `
			SELECT f.id, f.client_name, f.fact, f.tags, f.pinned, f.valid_to, f.superseded_by,
			       f.dormant_reason, f.source_quote, f.last_served_at, f.served_count, f.created_at
			FROM memory_facts_fts fts
			JOIN memory_facts f ON f.id = fts.rowid
			WHERE memory_facts_fts MATCH ?
			  AND f.client_name = ?
			  AND (
			      (f.valid_to IS NULL AND f.superseded_by IS NULL AND f.dormant_reason = '' AND f.pinned = 0)
			      OR f.superseded_by IS NOT NULL
			  )
			ORDER BY bm25(memory_facts_fts), f.id DESC
			LIMIT ?
		`, ftsExpr, clientName, candidateLimit)
		if err != nil {
			return nil, err
		}
		candidates, err := scanFacts(rows)
		_ = rows.Close()
		if err != nil {
			return nil, err
		}
		resolved, err := p.resolveFactLineage(ctx, clientName, candidates, limit)
		if err != nil {
			return nil, err
		}
		if len(resolved) > 0 {
			return resolved, nil
		}
	}

	// Fallback for short queries (< 3 runes) where SQLite trigram cannot index tokens.
	trimmed := strings.TrimSpace(query)
	if trimmed == "" || utf8.RuneCountInString(trimmed) >= 3 {
		return nil, nil
	}
	pattern := "%" + trimmed + "%"
	rows, err := p.readerDB.QueryContext(ctx, `
		SELECT id, client_name, fact, tags, pinned, valid_to, superseded_by,
		       dormant_reason, source_quote, last_served_at, served_count, created_at
		FROM memory_facts
		WHERE client_name = ?
		  AND (fact LIKE ? OR tags LIKE ?)
		  AND (
		      (valid_to IS NULL AND superseded_by IS NULL AND dormant_reason = '' AND pinned = 0)
		      OR superseded_by IS NOT NULL
		  )
		ORDER BY id DESC
		LIMIT ?
	`, clientName, pattern, pattern, candidateLimit)
	if err != nil {
		return nil, err
	}
	candidates, err := scanFacts(rows)
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	return p.resolveFactLineage(ctx, clientName, candidates, limit)
}

func (p *Plugin) resolveFactLineage(ctx context.Context, clientName string, candidates []Fact, limit int) ([]Fact, error) {
	if len(candidates) == 0 || limit <= 0 {
		return nil, nil
	}

	seen := make(map[int64]struct{}, limit)
	results := make([]Fact, 0, limit)

	for _, cand := range candidates {
		if len(results) >= limit {
			break
		}

		if cand.SupersededBy == nil {
			if cand.ValidTo == nil && cand.DormantReason == "" && !cand.Pinned {
				if _, dup := seen[cand.ID]; !dup {
					seen[cand.ID] = struct{}{}
					results = append(results, cand)
				}
			}
			continue
		}

		visited := map[int64]bool{cand.ID: true}
		currID := *cand.SupersededBy
		for hop := 1; hop <= maxSupersedeHops; hop++ {
			if visited[currID] {
				// Corrupted cyclic chain: abort safely without blocking.
				break
			}
			visited[currID] = true

			nextFact, err := p.queryFactByID(ctx, clientName, currID)
			if errors.Is(err, sql.ErrNoRows) {
				// Broken pointer or cross-client ID: drop safely.
				break
			}
			if err != nil {
				return nil, err
			}

			if nextFact.SupersededBy == nil {
				if nextFact.ValidTo == nil && nextFact.DormantReason == "" && !nextFact.Pinned {
					if _, dup := seen[nextFact.ID]; !dup {
						seen[nextFact.ID] = struct{}{}
						results = append(results, nextFact)
					}
				}
				break
			}

			currID = *nextFact.SupersededBy
		}
	}

	return results, nil
}

func (p *Plugin) queryFactByID(ctx context.Context, clientName string, factID int64) (Fact, error) {
	row := p.readerDB.QueryRowContext(ctx, `
		SELECT id, client_name, fact, tags, pinned, valid_to, superseded_by,
		       dormant_reason, source_quote, last_served_at, served_count, created_at
		FROM memory_facts
		WHERE id = ? AND client_name = ?
	`, factID, clientName)
	return scanSingleFact(row)
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

// enqueueServedFacts submits injected fact IDs to the bounded hit channel without blocking.
// If the channel is full or the plugin is closing, updates are dropped immediately.
func (p *Plugin) enqueueServedFacts(clientName string, pinned []Fact, dynamic []Fact) {
	total := len(pinned) + len(dynamic)
	if total == 0 || p.closed.Load() {
		return
	}
	ids := make([]int64, 0, total)
	for _, f := range pinned {
		ids = append(ids, f.ID)
	}
	for _, f := range dynamic {
		ids = append(ids, f.ID)
	}
	ev := servedHitEvent{
		clientName: clientName,
		factIDs:    ids,
		servedUnix: time.Now().Unix(),
	}
	select {
	case p.hitCh <- ev:
	default:
		p.droppedHits.Add(1)
	}
}

func (p *Plugin) hitWorker() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.hitFlushEvery)
	defer ticker.Stop()

	pending := make(map[hitKey]hitDelta)
	pendingEvents := 0

	accumulate := func(ev servedHitEvent) {
		for _, id := range ev.factIDs {
			k := hitKey{clientName: ev.clientName, factID: id}
			cur := pending[k]
			cur.count++
			if ev.servedUnix > cur.lastServed {
				cur.lastServed = ev.servedUnix
			}
			pending[k] = cur
		}
		pendingEvents++
	}

	flush := func() {
		if len(pending) == 0 {
			pendingEvents = 0
			return
		}
		flushed, err := p.flushHitDeltas(pending)
		if err != nil {
			log.Printf("[Memory] Failed flushing %d served-fact updates: %v", len(pending), err)
		} else {
			p.flushedHits.Add(flushed)
		}
		clear(pending)
		pendingEvents = 0
	}

	for {
		select {
		case ev := <-p.hitCh:
			accumulate(ev)
			if pendingEvents >= hitFlushBatchThreshold {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-p.stopCh:
			for {
				select {
				case ev := <-p.hitCh:
					accumulate(ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (p *Plugin) flushHitDeltas(deltas map[hitKey]hitDelta) (int64, error) {
	tx, err := p.writerDB.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		UPDATE memory_facts
		SET served_count = served_count + ?,
		    last_served_at = CASE
		        WHEN last_served_at IS NULL OR last_served_at < ? THEN ?
		        ELSE last_served_at
		    END
		WHERE id = ? AND client_name = ?
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var totalHits int64
	for k, d := range deltas {
		if _, err := stmt.Exec(d.count, d.lastServed, d.lastServed, k.factID, k.clientName); err != nil {
			return 0, err
		}
		totalHits += d.count
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return totalHits, nil
}

// DroppedHitCount returns the number of hit-tracking events dropped due to channel saturation.
func (p *Plugin) DroppedHitCount() int64 {
	return p.droppedHits.Load()
}

// FlushedHitCount returns the cumulative served_count increments persisted by the background worker.
func (p *Plugin) FlushedHitCount() int64 {
	return p.flushedHits.Load()
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

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSingleFact(s rowScanner) (Fact, error) {
	var (
		f              Fact
		pinnedInt      int
		validToUnix    sql.NullInt64
		supersededBy   sql.NullInt64
		lastServedUnix sql.NullInt64
	)
	if err := s.Scan(
		&f.ID,
		&f.ClientName,
		&f.Fact,
		&f.Tags,
		&pinnedInt,
		&validToUnix,
		&supersededBy,
		&f.DormantReason,
		&f.SourceQuote,
		&lastServedUnix,
		&f.ServedCount,
		&f.CreatedAt,
	); err != nil {
		return Fact{}, err
	}
	f.Pinned = pinnedInt != 0
	if validToUnix.Valid {
		t := time.Unix(validToUnix.Int64, 0)
		f.ValidTo = &t
	}
	if supersededBy.Valid {
		id := supersededBy.Int64
		f.SupersededBy = &id
	}
	if lastServedUnix.Valid {
		t := time.Unix(lastServedUnix.Int64, 0)
		f.LastServedAt = &t
	}
	return f, nil
}

func scanFacts(rows *sql.Rows) ([]Fact, error) {
	var facts []Fact
	for rows.Next() {
		f, err := scanSingleFact(rows)
		if err != nil {
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
