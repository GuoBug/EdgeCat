// Package proxy_test tests HTTP/SSE proxy flows, PII roundtripping,
// TTFT fallback, and strict JSON repair in EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/patchcat-dev/edgecat/internal/audit"
	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/contract"
	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/proxy"
	"github.com/patchcat-dev/edgecat/internal/router"
)

func TestProxy_HealthEndpoint(t *testing.T) {
	tempDir := t.TempDir()
	auditLogger, err := audit.NewLogger(filepath.Join(tempDir, "audit.db"), 10, 100, 100)
	if err != nil {
		t.Fatalf("init audit: %v", err)
	}
	defer auditLogger.Close()

	cfg := config.DefaultConfig()
	masker := filter.NewMasker(true, true, true, true)
	r := router.NewRouter(cfg)
	guard := contract.NewGuard(true, 1, 1000)

	h := proxy.NewHandler(cfg, masker, r, guard, auditLogger)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json parse error: %v", err)
	}
	if body["status"] != "healthy" {
		t.Fatalf("expected status healthy, got %v", body["status"])
	}
}

func TestProxy_NonStreaming_PIIRoundTrip(t *testing.T) {
	phone := "13800138000"
	var receivedUpstreamBody []byte

	// Mock upstream server that echoes placeholder
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUpstreamBody, _ = io.ReadAll(r.Body)

		resp := proxy.ChatCompletionResponse{
			ID:      "chatcmpl-test",
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   "qwen2.5:7b",
			Choices: []proxy.ChatChoice{
				{
					Index: 0,
					Message: proxy.ChatMessage{
						Role:    "assistant",
						Content: "Contact recorded for {{EC_PII_PHONE_1}} successfully.",
					},
					FinishReason: "stop",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	tempDir := t.TempDir()
	auditLogger, _ := audit.NewLogger(filepath.Join(tempDir, "audit.db"), 10, 100, 100)
	defer auditLogger.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = upstream.URL
	cfg.Local.MaxConcurrentLocal = 2
	cfg.Local.TTFTTimeoutMs = 3000

	masker := filter.NewMasker(true, true, true, true)
	r := router.NewRouter(cfg)
	guard := contract.NewGuard(true, 1, 1000)

	h := proxy.NewHandler(cfg, masker, r, guard, auditLogger)

	// Send request with raw phone number
	clientReq := proxy.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []proxy.ChatMessage{
			{Role: "user", Content: "Hello, my phone is " + phone},
		},
		Stream: false,
	}
	reqData, _ := json.Marshal(clientReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqData))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 1. Verify upstream received masked placeholder, NOT the raw phone
	if strings.Contains(string(receivedUpstreamBody), phone) {
		t.Fatalf("leak detected: upstream received raw phone number! Body: %s", string(receivedUpstreamBody))
	}
	if !strings.Contains(string(receivedUpstreamBody), "{{EC_PII_PHONE_1}}") {
		t.Fatalf("upstream did not receive placeholder: %s", string(receivedUpstreamBody))
	}

	// 2. Verify downstream client received rehydrated phone number
	var clientResp proxy.ChatCompletionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &clientResp); err != nil {
		t.Fatalf("failed to parse client response: %v", err)
	}

	expectedAnswer := "Contact recorded for " + phone + " successfully."
	if clientResp.Choices[0].Message.Content != expectedAnswer {
		t.Fatalf("expected rehydrated text %q, got %q", expectedAnswer, clientResp.Choices[0].Message.Content)
	}
}

func TestProxy_Streaming_TTFTFallbackToCloud(t *testing.T) {
	// Mock local server that stalls longer than TTFT timeout
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // exceeds 50ms TTFT
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"local\"}}]}\n\n"))
	}))
	defer localServer.Close()

	// Mock cloud server that responds fast
	cloudServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"cloud fallback success\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer cloudServer.Close()

	tempDir := t.TempDir()
	auditLogger, _ := audit.NewLogger(filepath.Join(tempDir, "audit.db"), 10, 100, 100)
	defer auditLogger.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = localServer.URL
	cfg.Local.TTFTTimeoutMs = 50 // strict 50ms TTFT timeout
	cfg.Cloud.Endpoint = cloudServer.URL

	masker := filter.NewMasker(true, true, true, true)
	r := router.NewRouter(cfg)
	guard := contract.NewGuard(true, 1, 1000)

	h := proxy.NewHandler(cfg, masker, r, guard, auditLogger)

	clientReq := proxy.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []proxy.ChatMessage{
			{Role: "user", Content: "Fast please"},
		},
		Stream: true,
	}
	reqData, _ := json.Marshal(clientReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqData))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "cloud fallback success") {
		t.Fatalf("expected stream to fallback and contain cloud content, got: %s", body)
	}

	// Verify route header indicates cloud
	if rec.Header().Get("X-EdgeCat-Route") != router.TargetCloud {
		t.Fatalf("expected route header cloud, got %s", rec.Header().Get("X-EdgeCat-Route"))
	}
}
