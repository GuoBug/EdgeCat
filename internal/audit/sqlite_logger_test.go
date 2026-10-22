// Package audit_test tests async batch persistence with modernc.org/sqlite.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package audit_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/patchcat-dev/edgecat/internal/audit"
)

func TestAsyncAuditLogger(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_audit.db")

	logger, err := audit.NewLogger(dbPath, 5, 100, 1000)
	if err != nil {
		t.Fatalf("failed to init audit logger: %v", err)
	}

	for i := 0; i < 12; i++ {
		ok := logger.Log(&audit.Record{
			RequestID:        "req_test",
			RouteTarget:      "local",
			Model:            "qwen2.5:7b",
			LatencyMs:        120,
			TTFTMs:           45,
			PIIRedactedCount: 1,
			Status:           200,
			CreatedAt:        time.Now().UTC(),
		})
		if !ok {
			t.Fatalf("failed to enqueue audit record %d", i)
		}
	}

	// Give a brief moment for worker ticker/batch
	time.Sleep(150 * time.Millisecond)

	if err := logger.Close(); err != nil {
		t.Fatalf("failed to close audit logger: %v", err)
	}

	if logger.WrittenCount() != 12 {
		t.Fatalf("expected 12 records written, got %d", logger.WrittenCount())
	}

	// Verify file was created
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("sqlite database file was not created: %v", err)
	}
}
