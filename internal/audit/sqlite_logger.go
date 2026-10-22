// Package audit provides asynchronous batch auditing to SQLite for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package audit

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Record represents a single governance audit entry.
type Record struct {
	RequestID        string
	RouteTarget      string // "local" or "cloud"
	Model            string
	LatencyMs        int64
	TTFTMs           int64
	PIIRedactedCount int
	Status           int // HTTP status code
	CreatedAt        time.Time
}

// Logger manages the background batch worker and SQLite database.
type Logger struct {
	db            *sql.DB
	records       chan *Record
	batchSize     int
	flushInterval time.Duration
	wg            sync.WaitGroup
	closed        atomic.Bool
	droppedCount  atomic.Int64
	writtenCount  atomic.Int64
}

// NewLogger initializes the SQLite database with WAL mode and launches the async worker.
func NewLogger(dbPath string, batchSize, flushIntervalMs, queueSize int) (*Logger, error) {
	if batchSize <= 0 {
		batchSize = 50
	}
	if flushIntervalMs <= 0 {
		flushIntervalMs = 1000
	}
	if queueSize <= 0 {
		queueSize = 10000
	}

	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create audit db directory: %w", err)
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// Set connection pool for single-writer SQLite WAL
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init sqlite schema: %w", err)
	}

	l := &Logger{
		db:            db,
		records:       make(chan *Record, queueSize),
		batchSize:     batchSize,
		flushInterval: time.Duration(flushIntervalMs) * time.Millisecond,
	}

	l.wg.Add(1)
	go l.worker()

	return l, nil
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_id TEXT NOT NULL,
		route_target TEXT NOT NULL,
		model TEXT NOT NULL,
		latency_ms INTEGER NOT NULL,
		ttft_ms INTEGER NOT NULL,
		pii_redacted_count INTEGER NOT NULL,
		status INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
	`
	_, err := db.Exec(schema)
	return err
}

// Log enqueues an audit record without blocking the calling HTTP goroutine.
// If the buffer is full, it increments droppedCount and drops the record to preserve low latency.
func (l *Logger) Log(r *Record) bool {
	if l == nil || l.closed.Load() {
		return false
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}

	select {
	case l.records <- r:
		return true
	default:
		l.droppedCount.Add(1)
		return false
	}
}

// DroppedCount returns the count of dropped records due to queue saturation.
func (l *Logger) DroppedCount() int64 {
	return l.droppedCount.Load()
}

// WrittenCount returns the total number of successfully written audit records.
func (l *Logger) WrittenCount() int64 {
	return l.writtenCount.Load()
}

// worker runs continuously in the background, flushing records on batch limit or timer.
func (l *Logger) worker() {
	defer l.wg.Done()

	ticker := time.NewTicker(l.flushInterval)
	defer ticker.Stop()

	batch := make([]*Record, 0, l.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := l.writeBatch(batch); err != nil {
			log.Printf("[Audit] Error flushing %d audit records: %v", len(batch), err)
		} else {
			l.writtenCount.Add(int64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case r, ok := <-l.records:
			if !ok {
				// Channel closed, flush remaining items and exit
				flush()
				return
			}
			batch = append(batch, r)
			if len(batch) >= l.batchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// writeBatch inserts a batch of records inside a single SQLite transaction.
func (l *Logger) writeBatch(batch []*Record) error {
	if len(batch) == 0 {
		return nil
	}

	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO audit_logs (
			request_id, route_target, model, latency_ms, ttft_ms, pii_redacted_count, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert statement: %w", err)
	}
	defer stmt.Close()

	for _, r := range batch {
		_, err := stmt.Exec(
			r.RequestID,
			r.RouteTarget,
			r.Model,
			r.LatencyMs,
			r.TTFTMs,
			r.PIIRedactedCount,
			r.Status,
			r.CreatedAt.Format("2006-01-02 15:04:05"),
		)
		if err != nil {
			return fmt.Errorf("execute batch insert: %w", err)
		}
	}

	return tx.Commit()
}

// Close gracefully stops the worker, flushes remaining records, and closes the database.
func (l *Logger) Close() error {
	if l == nil || l.closed.Swap(true) {
		return nil
	}
	close(l.records)
	l.wg.Wait()
	return l.db.Close()
}
