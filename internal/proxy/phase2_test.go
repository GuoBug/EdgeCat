package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/router"
)

// TestProxy_Phase2_DynamicModels verifies D5: Logical models are dynamically discovered
// from local/cloud mappings while physical names (e.g. qwen2.5:7b) are never exposed.
func TestProxy_Phase2_DynamicModels(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Local.ModelMapping = map[string]string{
		"coding":   "qwen2.5-coder:7b",
		"analysis": "qwen2.5:14b",
	}
	cfg.Cloud.ModelMapping = map[string]string{
		"coding":  "deepseek-coder",
		"writing": "claude-3-5-sonnet",
	}

	h := newTestHandler(t, cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode models response: %v", err)
	}

	found := make(map[string]bool)
	for _, m := range resp.Data {
		found[m.ID] = true
	}

	// Must contain logical keys
	for _, expected := range []string{"default", "coding", "analysis", "writing"} {
		if !found[expected] {
			t.Errorf("expected logical model %q in /v1/models, but missing", expected)
		}
	}

	// Must NOT expose internal physical model names
	for _, physical := range []string{"qwen2.5-coder:7b", "qwen2.5:14b", "deepseek-coder", "claude-3-5-sonnet"} {
		if found[physical] {
			t.Errorf("physical model name %q leaked in /v1/models", physical)
		}
	}
}

// TestProxy_Phase2_AuthToken verifies R2.2: Bearer token auth is enforced when enabled,
// while /health remains accessible without credentials.
func TestProxy_Phase2_AuthToken(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.Clients = []config.ClientConfig{
		{Name: "macbook-pro", Token: "ec-secret-token-1"},
	}

	h := newTestHandler(t, cfg)

	// 1. /health should be open for liveness
	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthRec := httptest.NewRecorder()
	h.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("/health must be accessible without token, got status %d", healthRec.Code)
	}

	// 2. /v1/chat/completions without token returns 401
	unauthReq := `{"model":"default","messages":[{"role":"user","content":"hi"}]}`
	recUnauth := postChatCompletion(t, h, unauthReq, nil)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d: %s", recUnauth.Code, recUnauth.Body.String())
	}

	// 3. Invalid token returns 401
	recBad := postChatCompletion(t, h, unauthReq, map[string]string{
		"Authorization": "Bearer wrong-token",
	})
	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad token, got %d", recBad.Code)
	}
}

// TestProxy_Phase2_CORS_And_ChromePNA verifies R2.4: CORS preflights, headers,
// and Chrome Private Network Access header injection.
func TestProxy_Phase2_CORS_And_ChromePNA(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.AllowedOrigins = []string{"https://patchcat.dev", "http://localhost:5173"}

	h := newTestHandler(t, cfg)

	// Preflight OPTIONS with Chrome PNA header
	optReq := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	optReq.Header.Set("Origin", "https://patchcat.dev")
	optReq.Header.Set("Access-Control-Request-Private-Network", "true")
	optRec := httptest.NewRecorder()
	h.ServeHTTP(optRec, optReq)

	if optRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for OPTIONS, got %d", optRec.Code)
	}
	if optRec.Header().Get("Access-Control-Allow-Origin") != "https://patchcat.dev" {
		t.Fatalf("expected allow origin https://patchcat.dev, got %q", optRec.Header().Get("Access-Control-Allow-Origin"))
	}
	if optRec.Header().Get("Access-Control-Allow-Private-Network") != "true" {
		t.Fatalf("expected Access-Control-Allow-Private-Network: true, got %q", optRec.Header().Get("Access-Control-Allow-Private-Network"))
	}

	// Disallowed origin should not have CORS header
	disallowedReq := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	disallowedReq.Header.Set("Origin", "https://evil-site.com")
	disallowedRec := httptest.NewRecorder()
	h.ServeHTTP(disallowedRec, disallowedReq)
	if disallowedRec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed origin must not receive Access-Control-Allow-Origin header")
	}
}

// TestProxy_Phase2_CloudQuotaEnforcement verifies R2.3, D1, D3:
// Local calls consume 0 quota; Cloud fallback triggers quota check before writing headers;
// daily_cloud_limit=-1 returns 503; exceeding limit returns 429.
func TestProxy_Phase2_CloudQuotaEnforcement(t *testing.T) {
	// Mock local that always fails
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer localServer.Close()

	// Mock cloud that succeeds
	var cloudCalls int
	cloudServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cloudCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"cloud ok"},"finish_reason":"stop"}]}`))
	}))
	defer cloudServer.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = localServer.URL
	cfg.Cloud.Endpoint = cloudServer.URL
	cfg.Auth.Enabled = true
	cfg.Auth.Clients = []config.ClientConfig{
		{Name: "client-local-only", Token: "token-local-only", DailyCloudLimit: -1},
		{Name: "client-capped", Token: "token-capped", DailyCloudLimit: 1},
	}

	h := newTestHandler(t, cfg)
	reqBody := `{"model":"default","messages":[{"role":"user","content":"test"}]}`

	// 1. Client with daily_cloud_limit: -1 should receive 503 when local fails (D3)
	rec1 := postChatCompletion(t, h, reqBody, map[string]string{"Authorization": "Bearer token-local-only"})
	if rec1.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for local-only client on fallback, got %d: %s", rec1.Code, rec1.Body.String())
	}
	if cloudCalls != 0 {
		t.Fatalf("cloud should not have been called for local-only client, calls=%d", cloudCalls)
	}

	// 2. Client with limit=1: first fallback succeeds (429 not triggered)
	rec2 := postChatCompletion(t, h, reqBody, map[string]string{"Authorization": "Bearer token-capped"})
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 for 1st call, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if cloudCalls != 1 {
		t.Fatalf("expected 1 cloud call, got %d", cloudCalls)
	}

	// 3. Client with limit=1: second fallback hits 429 quota exceeded (D1 pre-header window)
	rec3 := postChatCompletion(t, h, reqBody, map[string]string{"Authorization": "Bearer token-capped"})
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for 2nd call, got %d: %s", rec3.Code, rec3.Body.String())
	}
	if !strings.Contains(rec3.Body.String(), "daily_cloud_limit_exceeded") {
		t.Fatalf("expected error code daily_cloud_limit_exceeded, got %s", rec3.Body.String())
	}
	if cloudCalls != 1 {
		t.Fatalf("cloud tier should not have been called on quota breach, calls=%d", cloudCalls)
	}
}

// TestProxy_Phase2_LocalCallsDoNotConsumeCloudQuota verifies that free local
// inference does not decrement or check cloud limits.
func TestProxy_Phase2_LocalCallsDoNotConsumeCloudQuota(t *testing.T) {
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"local free"},"finish_reason":"stop"}]}`))
	}))
	defer localServer.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = localServer.URL
	cfg.Auth.Enabled = true
	cfg.Auth.Clients = []config.ClientConfig{
		{Name: "alice", Token: "token-alice", DailyCloudLimit: 1},
	}

	h := newTestHandler(t, cfg)
	reqBody := `{"model":"default","messages":[{"role":"user","content":"test"}]}`

	// Execute 5 local requests with limit=1
	for i := 0; i < 5; i++ {
		rec := postChatCompletion(t, h, reqBody, map[string]string{"Authorization": "Bearer token-alice"})
		if rec.Code != http.StatusOK {
			t.Fatalf("local call %d failed with status %d: %s", i+1, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-EdgeCat-Route") != router.TargetLocal {
			t.Fatalf("expected route local, got %s", rec.Header().Get("X-EdgeCat-Route"))
		}
	}
}
