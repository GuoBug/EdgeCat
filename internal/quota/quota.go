// Package quota implements dual-track quota enforcement with persistent SQLite counters.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package quota

import (
	"database/sql"
	"sync"
	"time"

	"github.com/patchcat-dev/edgecat/internal/config"
)

// Status represents the quota check outcome.
type Status int

const (
	StatusAllowed Status = iota
	StatusQuotaExceeded
	StatusLocalOnlyDisallowed
)

// Manager handles in-memory fast atomic checks and SQLite persistence for daily cloud quotas.
type Manager struct {
	db     *sql.DB
	limits map[string]int // clientName -> daily_cloud_limit
	mu     sync.RWMutex
	counts map[string]map[string]int // dateStr (YYYY-MM-DD) -> clientName -> count
}

// NewManager initializes the quota manager, loading today's persistent counters from SQLite.
func NewManager(db *sql.DB, clients []config.ClientConfig) (*Manager, error) {
	limits := make(map[string]int)
	for _, c := range clients {
		limits[c.Name] = c.DailyCloudLimit
	}

	m := &Manager{
		db:     db,
		limits: limits,
		counts: make(map[string]map[string]int),
	}

	today := m.currentDateString()
	m.counts[today] = make(map[string]int)

	if db != nil {
		rows, err := db.Query("SELECT client_name, cloud_calls FROM daily_client_cloud_usage WHERE usage_date = ?", today)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var client string
				var count int
				if err := rows.Scan(&client, &count); err == nil {
					m.counts[today][client] = count
				}
			}
		}
	}

	return m, nil
}

// currentDateString returns the current calendar date in local server timezone (D4: local day expectation).
func (m *Manager) currentDateString() string {
	return time.Now().Format("2006-01-02")
}

// NextResetTime returns the next midnight reset timestamp in local server timezone.
func (m *Manager) NextResetTime() time.Time {
	now := time.Now()
	nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	return nextMidnight
}

// CheckAndIncrementCloud tests if a client can make a cloud call, and if so, atomically consumes 1 quota.
// This is called strictly in the pre-WriteHeader decision window when routing or falling back to Cloud Tier (D1).
func (m *Manager) CheckAndIncrementCloud(clientName string) Status {
	if clientName == "" {
		clientName = "anonymous"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	limit, hasLimit := m.limits[clientName]
	// D3: daily_cloud_limit == -1 explicitly disallows cloud fallback (local only)
	if hasLimit && limit == -1 {
		return StatusLocalOnlyDisallowed
	}

	// 0 or not configured indicates unlimited cloud usage
	if !hasLimit || limit == 0 {
		m.incrementLocked(clientName)
		return StatusAllowed
	}

	today := m.currentDateString()
	todayMap, exists := m.counts[today]
	if !exists {
		todayMap = make(map[string]int)
		m.counts[today] = todayMap
	}

	currentUsage := todayMap[clientName]
	if currentUsage >= limit {
		return StatusQuotaExceeded
	}

	todayMap[clientName]++
	newCount := todayMap[clientName]

	// Persist asynchronously/synchronously to SQLite (D2)
	if m.db != nil {
		go func(client, date string, count int) {
			query := `
				INSERT INTO daily_client_cloud_usage (client_name, usage_date, cloud_calls, updated_at)
				VALUES (?, ?, ?, CURRENT_TIMESTAMP)
				ON CONFLICT(client_name, usage_date) DO UPDATE SET
					cloud_calls = ?,
					updated_at = CURRENT_TIMESTAMP;
			`
			_, _ = m.db.Exec(query, client, date, count, count)
		}(clientName, today, newCount)
	}

	return StatusAllowed
}

func (m *Manager) incrementLocked(clientName string) {
	today := m.currentDateString()
	todayMap, exists := m.counts[today]
	if !exists {
		todayMap = make(map[string]int)
		m.counts[today] = todayMap
	}
	todayMap[clientName]++
	newCount := todayMap[clientName]

	if m.db != nil {
		go func(client, date string, count int) {
			query := `
				INSERT INTO daily_client_cloud_usage (client_name, usage_date, cloud_calls, updated_at)
				VALUES (?, ?, ?, CURRENT_TIMESTAMP)
				ON CONFLICT(client_name, usage_date) DO UPDATE SET
					cloud_calls = ?,
					updated_at = CURRENT_TIMESTAMP;
			`
			_, _ = m.db.Exec(query, client, date, count, count)
		}(clientName, today, newCount)
	}
}

// ClientUsageSummary returns current usage stats for health check aggregation.
func (m *Manager) ClientUsageSummary() map[string]map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	today := m.currentDateString()
	todayMap := m.counts[today]

	summary := make(map[string]map[string]any)

	// Include all configured clients
	for client, limit := range m.limits {
		used := 0
		if todayMap != nil {
			used = todayMap[client]
		}
		var remaining any = "unlimited"
		if limit > 0 {
			rem := limit - used
			if rem < 0 {
				rem = 0
			}
			remaining = rem
		} else if limit == -1 {
			remaining = "disabled (local only)"
		}

		summary[client] = map[string]any{
			"daily_cloud_limit": limit,
			"today_cloud_calls": used,
			"remaining":         remaining,
		}
	}

	// Also include anonymous or dynamic clients if used
	if todayMap != nil {
		for client, used := range todayMap {
			if _, exists := summary[client]; !exists {
				summary[client] = map[string]any{
					"daily_cloud_limit": 0,
					"today_cloud_calls": used,
					"remaining":         "unlimited",
				}
			}
		}
	}

	return summary
}

// LimitForClient returns the configured limit for a given client.
func (m *Manager) LimitForClient(clientName string) (int, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit, ok := m.limits[clientName]
	return limit, ok
}
