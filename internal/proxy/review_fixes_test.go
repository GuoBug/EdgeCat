// Package proxy_test tests stream SSE PII rehydration, CORS default deny,
// /health split, and request body limits.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/proxy"
)

// TestStreamRehydrator_Unit verifies unit behavior of StreamRehydrator directly.
func TestStreamRehydrator_Unit(t *testing.T) {
	vault := filter.NewVault()
	phone := "13800138000"
	ph := vault.Mask(filter.TypePhone, phone)
	if ph != "{{EC_PII_PHONE_1}}" {
		t.Fatalf("expected placeholder {{EC_PII_PHONE_1}}, got %s", ph)
	}

	rehydrator := proxy.NewStreamRehydrator(vault)

	// Chunk 1: content has prefix of placeholder
	c1JSON := `{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"Phone: {{EC_PI"}}]}`
	out1 := rehydrator.ProcessJSONLine("data: "+c1JSON, c1JSON)

	var obj1 map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(out1, "data: ")), &obj1); err != nil {
		t.Fatalf("failed to parse obj1: %v", err)
	}
	choices1 := obj1["choices"].([]any)
	delta1 := choices1[0].(map[string]any)["delta"].(map[string]any)
	if delta1["content"] != "Phone: " {
		t.Fatalf("expected chunk 1 content to be 'Phone: ', got %q", delta1["content"])
	}

	// Chunk 2: content completes the placeholder
	c2JSON := `{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"I_PHONE_1}} ready."}}]}`
	out2 := rehydrator.ProcessJSONLine("data: "+c2JSON, c2JSON)

	var obj2 map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(out2, "data: ")), &obj2); err != nil {
		t.Fatalf("failed to parse obj2: %v", err)
	}
	choices2 := obj2["choices"].([]any)
	delta2 := choices2[0].(map[string]any)["delta"].(map[string]any)
	if delta2["content"] != "13800138000 ready." {
		t.Fatalf("expected chunk 2 content to be '13800138000 ready.', got %q", delta2["content"])
	}

	// Flush should have nothing remaining
	tails := rehydrator.FlushPendingChunks()
	if len(tails) != 0 {
		t.Fatalf("expected no leftover tail, got %v", tails)
	}
}

// TestProxy_Streaming_PII_SplitAcrossSSEFrames reproduces and fixes the critical issue:
// A model emitting tokens that split a placeholder across adjacent SSE frames
// must have the original PII fully restored on the client side.
func TestProxy_Streaming_PII_SplitAcrossSSEFrames(t *testing.T) {
	const phone = "13800138000"
	var receivedUpstreamBody string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedUpstreamBody = string(body)

		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		// Frame 1: start of placeholder split
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-s1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Contact: {{EC_PI\"},\"finish_reason\":null}]}\n\n"))
		flusher.Flush()

		// Frame 2: end of placeholder and rest of sentence
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-s1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"I_PHONE_1}} now.\"},\"finish_reason\":null}]}\n\n"))
		flusher.Flush()

		// Frame 3: done
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = upstream.URL
	cfg.Cloud.Endpoint = upstream.URL

	h := newTestHandler(t, cfg)

	reqBody := `{"model":"default","stream":true,"messages":[{"role":"user","content":"Call me at 13800138000"}]}`
	rec := postChatCompletion(t, h, reqBody, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify upstream received masked placeholder
	if strings.Contains(receivedUpstreamBody, phone) {
		t.Fatalf("upstream received unmasked phone number: %s", receivedUpstreamBody)
	}
	if !strings.Contains(receivedUpstreamBody, "{{EC_PII_PHONE_1}}") {
		t.Fatalf("upstream missing placeholder: %s", receivedUpstreamBody)
	}

	clientResp := rec.Body.String()

	// Verify client received rehydrated phone number
	if !strings.Contains(clientResp, phone) {
		t.Fatalf("client did not receive rehydrated phone number!\nResponse:\n%s", clientResp)
	}
	// Verify no raw placeholder leaked to client
	if strings.Contains(clientResp, "{{EC_PII_") {
		t.Fatalf("client received un-rehydrated placeholder!\nResponse:\n%s", clientResp)
	}
}

// TestProxy_Streaming_ReasoningAndToolCalls_SplitAcrossSSEFrames tests
// placeholder splitting in reasoning_content and streaming tool_calls arguments.
func TestProxy_Streaming_ReasoningAndToolCalls_SplitAcrossSSEFrames(t *testing.T) {
	const phone = "13800138000"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)

		// Reasoning frame 1
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-r1\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"Verify {{EC_PI\"}}]}\n\n"))
		flusher.Flush()

		// Reasoning frame 2
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-r1\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"I_PHONE_1}} done\"}}]}\n\n"))
		flusher.Flush()

		// Tool call frame 1
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-r1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"tel\\\":\\\"{{EC_\"}}]}}]}\n\n"))
		flusher.Flush()

		// Tool call frame 2
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-r1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"PII_PHONE_1}}\\\"}\"}}]}}]}\n\n"))
		flusher.Flush()

		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = upstream.URL
	cfg.Cloud.Endpoint = upstream.URL

	h := newTestHandler(t, cfg)

	reqBody := `{"model":"default","stream":true,"messages":[{"role":"user","content":"Call 13800138000"}]}`
	rec := postChatCompletion(t, h, reqBody, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	clientResp := rec.Body.String()
	if !strings.Contains(clientResp, phone) {
		t.Fatalf("expected phone %q to be rehydrated in stream, got:\n%s", phone, clientResp)
	}
	if strings.Contains(clientResp, "{{EC_PII_") {
		t.Fatalf("raw placeholder leaked in stream:\n%s", clientResp)
	}
}

// TestProxy_CORS_DefaultDeny verifies that without an explicit allowlist,
// cross-origin requests from arbitrary web origins are denied.
func TestProxy_CORS_DefaultDeny(t *testing.T) {
	cfg := config.DefaultConfig()
	// AllowedOrigins is empty by default
	if len(cfg.Server.AllowedOrigins) != 0 {
		t.Fatalf("expected AllowedOrigins to default to empty, got %v", cfg.Server.AllowedOrigins)
	}

	h := newTestHandler(t, cfg)

	// Preflight OPTIONS from arbitrary origin must be rejected with 403 Forbidden
	optReq := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	optReq.Header.Set("Origin", "https://malicious-webpage.com")
	optReq.Header.Set("Access-Control-Request-Private-Network", "true")
	optRec := httptest.NewRecorder()
	h.ServeHTTP(optRec, optReq)

	if optRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disallowed CORS preflight, got %d", optRec.Code)
	}
	if optRec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("must not set Access-Control-Allow-Origin for disallowed origin")
	}
	if optRec.Header().Get("Access-Control-Allow-Private-Network") != "" {
		t.Fatalf("must not set Access-Control-Allow-Private-Network for disallowed origin")
	}

	// Regular request with Origin header must not receive CORS allow headers
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://malicious-webpage.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("must not set Access-Control-Allow-Origin for disallowed origin on GET")
	}
}

// TestProxy_HealthSplit_And_AdminStatus verifies that /health is a minimal public liveness check,
// while detailed metrics and tier configurations are isolated under /admin/status with authentication.
func TestProxy_HealthSplit_And_AdminStatus(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.Clients = []config.ClientConfig{
		{
			Name:            "admin-client",
			Token:           "secret-token-123",
			DailyCloudLimit: 100,
		},
	}
	cfg.Local.Endpoint = "http://192.168.1.100:11434/v1"
	cfg.Cloud.Endpoint = "https://api.openai.com/v1"

	h := newTestHandler(t, cfg)

	// 1. Public /health check without token
	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthRec := httptest.NewRecorder()
	h.ServeHTTP(healthRec, healthReq)

	if healthRec.Code != http.StatusOK {
		t.Fatalf("/health must be accessible without auth, got status %d", healthRec.Code)
	}

	var healthBody map[string]any
	if err := json.Unmarshal(healthRec.Body.Bytes(), &healthBody); err != nil {
		t.Fatalf("failed to decode /health json: %v", err)
	}
	if healthBody["status"] != "healthy" {
		t.Fatalf("expected status healthy, got %v", healthBody["status"])
	}
	// Verify /health does NOT leak local/cloud endpoints or client usage
	if _, exists := healthBody["local_tier"]; exists {
		t.Fatalf("/health must not leak local_tier")
	}
	if _, exists := healthBody["cloud_tier"]; exists {
		t.Fatalf("/health must not leak cloud_tier")
	}
	if _, exists := healthBody["clients_usage"]; exists {
		t.Fatalf("/health must not leak clients_usage")
	}

	// 2. /admin/status without token must return 401 Unauthorized
	adminUnauthReq := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	adminUnauthRec := httptest.NewRecorder()
	h.ServeHTTP(adminUnauthRec, adminUnauthReq)
	if adminUnauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /admin/status, got %d", adminUnauthRec.Code)
	}

	// 3. /admin/status with valid token returns full telemetry
	adminAuthedReq := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	adminAuthedReq.Header.Set("Authorization", "Bearer secret-token-123")
	adminAuthedRec := httptest.NewRecorder()
	h.ServeHTTP(adminAuthedRec, adminAuthedReq)

	if adminAuthedRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated /admin/status, got %d", adminAuthedRec.Code)
	}

	var adminBody map[string]any
	if err := json.Unmarshal(adminAuthedRec.Body.Bytes(), &adminBody); err != nil {
		t.Fatalf("failed to decode /admin/status json: %v", err)
	}
	if adminBody["status"] != "healthy" {
		t.Fatalf("expected status healthy, got %v", adminBody["status"])
	}
	if _, exists := adminBody["local_tier"]; !exists {
		t.Fatalf("/admin/status should expose local_tier for admin")
	}
	if _, exists := adminBody["cloud_tier"]; !exists {
		t.Fatalf("/admin/status should expose cloud_tier for admin")
	}
	if _, exists := adminBody["clients_usage"]; !exists {
		t.Fatalf("/admin/status should expose clients_usage for admin")
	}
}

// TestProxy_RequestBodyLimit verifies that requests exceeding max_request_body_bytes
// are rejected with HTTP 413 Payload Too Large.
func TestProxy_RequestBodyLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.MaxRequestBodyBytes = 256 // small 256 byte limit for testing

	h := newTestHandler(t, cfg)

	// Large body (> 256 bytes)
	largeBody := `{"model":"default","messages":[{"role":"user","content":"` + strings.Repeat("A", 500) + `"}]}`
	rec := postChatCompletion(t, h, largeBody, nil)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Payload Too Large, got %d: %s", rec.Code, rec.Body.String())
	}

	var errResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	errObj, ok := errResp["error"].(map[string]any)
	if !ok || errObj["code"] != "payload_too_large" {
		t.Fatalf("expected error code payload_too_large, got %v", errResp)
	}
}
