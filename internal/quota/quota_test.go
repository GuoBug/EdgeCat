package quota_test

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/quota"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_quota.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	schema := `
	CREATE TABLE IF NOT EXISTS daily_client_cloud_usage (
		client_name TEXT NOT NULL,
		usage_date TEXT NOT NULL,
		cloud_calls INTEGER NOT NULL DEFAULT 0,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (client_name, usage_date)
	);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	return db
}

func TestQuotaManager_Enforcement(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	clients := []config.ClientConfig{
		{Name: "alice-pc", DailyCloudLimit: 2},
		{Name: "bob-phone", DailyCloudLimit: -1},   // local only (D3)
		{Name: "charlie-free", DailyCloudLimit: 0}, // unlimited
	}

	qm, err := quota.NewManager(db, clients)
	if err != nil {
		t.Fatalf("failed to create quota manager: %v", err)
	}

	// 1. Bob is local-only
	if status := qm.CheckAndIncrementCloud("bob-phone"); status != quota.StatusLocalOnlyDisallowed {
		t.Fatalf("expected StatusLocalOnlyDisallowed for bob, got %v", status)
	}

	// 2. Alice limit is 2
	if status := qm.CheckAndIncrementCloud("alice-pc"); status != quota.StatusAllowed {
		t.Fatalf("expected 1st call allowed for alice, got %v", status)
	}
	if status := qm.CheckAndIncrementCloud("alice-pc"); status != quota.StatusAllowed {
		t.Fatalf("expected 2nd call allowed for alice, got %v", status)
	}
	if status := qm.CheckAndIncrementCloud("alice-pc"); status != quota.StatusQuotaExceeded {
		t.Fatalf("expected 3rd call exceeded for alice, got %v", status)
	}

	// 3. Charlie is unlimited
	for i := 0; i < 10; i++ {
		if status := qm.CheckAndIncrementCloud("charlie-free"); status != quota.StatusAllowed {
			t.Fatalf("expected unlimited call %d allowed for charlie, got %v", i, status)
		}
	}
	qm.Close()
}

func TestQuotaManager_ConcurrentPersistAndRefund(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	db.SetMaxOpenConns(1)

	clients := []config.ClientConfig{
		{Name: "nas-user", DailyCloudLimit: 200},
	}

	qm, err := quota.NewManager(db, clients)
	if err != nil {
		t.Fatalf("failed to create quota manager: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if status := qm.CheckAndIncrementCloud("nas-user"); status != quota.StatusAllowed {
				t.Errorf("unexpected status: %v", status)
				return
			}
			if idx%10 == 0 {
				qm.RefundCloud("nas-user")
			}
		}(i)
	}
	wg.Wait()
	qm.Close()

	// Re-open Manager against the same DB to verify persisted count == 90 (100 - 10 refunds)
	qm2, err := quota.NewManager(db, clients)
	if err != nil {
		t.Fatalf("failed to reload quota manager: %v", err)
	}
	defer qm2.Close()

	summary := qm2.ClientUsageSummary()
	used := summary["nas-user"]["today_cloud_calls"]
	if used != 90 {
		t.Fatalf("expected persisted usage 90 after 100 increments and 10 refunds, got %v", used)
	}
}
