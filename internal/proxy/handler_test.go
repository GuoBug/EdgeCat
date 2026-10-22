// Package proxy_test tests HTTP/SSE proxy flows, PII roundtripping,
// TTFT fallback, lossless protocol passthrough, and strict JSON repair.
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/patchcat-dev/edgecat/internal/audit"
	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/contract"
	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/proxy"
	"github.com/patchcat-dev/edgecat/internal/router"
)

// newTestHandler wires a handler against the given config, with an isolated
// audit database and a masker that follows the config flags.
func newTestHandler(t *testing.T, cfg *config.Config) *proxy.Handler {
	t.Helper()

	logger, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.db"), 10, 100, 100)
	if err != nil {
		t.Fatalf("init audit logger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	masker := filter.NewMasker(cfg.Filter.MaskPhone, cfg.Filter.MaskEmail, cfg.Filter.MaskIPv4, cfg.Filter.MaskAPIKey)
	guard := contract.NewGuard(cfg.Contract.StrictJSONEnabled, cfg.Contract.MaxRepairAttempts, cfg.Contract.RepairTimeoutMs)

	return proxy.NewHandler(cfg, masker, router.NewRouter(cfg), guard, logger)
}

// postChatCompletion sends a raw JSON body to the chat completions endpoint.
func postChatCompletion(t *testing.T, h http.Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProxy_HealthEndpoint(t *testing.T) {
	h := newTestHandler(t, config.DefaultConfig())

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
	const phone = "13800138000"
	var receivedUpstreamBody []byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUpstreamBody, _ = io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test","object":"chat.completion","created":1750000000,` +
			`"model":"qwen2.5:7b","choices":[{"index":0,"message":{"role":"assistant",` +
			`"content":"Contact recorded for {{EC_PII_PHONE_1}} successfully."},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = upstream.URL
	cfg.Local.MaxConcurrentLocal = 2
	cfg.Local.TTFTTimeoutMs = 3000

	h := newTestHandler(t, cfg)

	rec := postChatCompletion(t, h, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello, my phone is `+phone+`"}],"stream":false}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 1. Upstream must receive the placeholder, never the raw phone number.
	if strings.Contains(string(receivedUpstreamBody), phone) {
		t.Fatalf("leak detected: upstream received raw phone number! Body: %s", string(receivedUpstreamBody))
	}
	if !strings.Contains(string(receivedUpstreamBody), "{{EC_PII_PHONE_1}}") {
		t.Fatalf("upstream did not receive placeholder: %s", string(receivedUpstreamBody))
	}

	// 2. Client must receive the rehydrated phone number.
	if !strings.Contains(rec.Body.String(), phone) {
		t.Fatalf("expected rehydrated phone in client response, got: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "{{EC_PII_") {
		t.Fatalf("placeholder leaked to client: %s", rec.Body.String())
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

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = localServer.URL
	cfg.Local.TTFTTimeoutMs = 50 // strict 50ms TTFT timeout
	cfg.Cloud.Endpoint = cloudServer.URL

	h := newTestHandler(t, cfg)

	rec := postChatCompletion(t, h, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Fast please"}],"stream":true}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "cloud fallback success") {
		t.Fatalf("expected stream to fallback and contain cloud content, got: %s", rec.Body.String())
	}
	if rec.Header().Get("X-EdgeCat-Route") != router.TargetCloud {
		t.Fatalf("expected route header cloud, got %s", rec.Header().Get("X-EdgeCat-Route"))
	}
}

// TestProxy_RequestPassthrough covers the lossless request path: tool calling
// fields and multimodal content parts must reach the upstream untouched, while
// their text payloads are still redacted.
func TestProxy_RequestPassthrough(t *testing.T) {
	var upstreamBody string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		upstreamBody = string(raw)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = upstream.URL
	h := newTestHandler(t, cfg)

	reqBody := `{
		"model":"gpt-4o-mini",
		"stream":false,
		"temperature":0.2,
		"top_p":0.9,
		"presence_penalty":0.5,
		"seed":42,
		"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}],
		"tool_choice":"auto",
		"messages":[
			{"role":"user","content":[
				{"type":"text","text":"我的电话是 13800138000，看看这张图"},
				{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}
			]},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"上海\",\"phone\":\"13800138000\"}"}}]}
		]
	}`

	rec := postChatCompletion(t, h, reqBody, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("multimodal request must not be rejected, got %d: %s", rec.Code, rec.Body.String())
	}

	mustContain := []string{
		`"tools"`, `"tool_choice"`, `"top_p"`, `"presence_penalty"`, `"seed"`,
		`"tool_calls"`, `"get_weather"`, `"image_url"`, `"data:image/png;base64,iVBORw0KGgo="`,
		`"temperature"`,
	}
	for _, want := range mustContain {
		if !strings.Contains(upstreamBody, want) {
			t.Fatalf("upstream payload lost %s\npayload: %s", want, upstreamBody)
		}
	}

	if strings.Contains(upstreamBody, "13800138000") {
		t.Fatalf("raw phone number leaked upstream: %s", upstreamBody)
	}
	if !strings.Contains(upstreamBody, "{{EC_PII_PHONE_1}}") {
		t.Fatalf("multimodal text part was not masked: %s", upstreamBody)
	}
}

// TestProxy_ResponsePassthrough covers the lossless response path: tool_calls,
// reasoning_content and unknown vendor fields must survive.
func TestProxy_ResponsePassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-x","object":"chat.completion","created":1750000000,"model":"qwen2.5:7b",
			"system_fingerprint":"fp_abc",
			"choices":[{
				"index":0,
				"message":{
					"role":"assistant",
					"content":"",
					"reasoning_content":"用户想查天气，需要调用工具",
					"tool_calls":[{"id":"call_9","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"上海\"}"}}]
				},
				"logprobs":{"content":[]},
				"finish_reason":"tool_calls"
			}],
			"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20,"prompt_tokens_details":{"cached_tokens":0}}
		}`))
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = upstream.URL
	h := newTestHandler(t, cfg)

	rec := postChatCompletion(t, h, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"上海天气"}],"stream":false}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	mustContain := []string{
		`"reasoning_content"`, `"tool_calls"`, `"get_weather"`, `"finish_reason":"tool_calls"`,
		`"logprobs"`, `"system_fingerprint"`, `"prompt_tokens_details"`,
		`"created":1750000000`,
	}
	for _, want := range mustContain {
		if !strings.Contains(body, want) {
			t.Fatalf("client response lost %s\npayload: %s", want, body)
		}
	}
}

// TestProxy_StrictJSON_MasterSwitchOff proves contract.strict_json_enabled is a
// real gate: when disabled, a fenced payload must be forwarded untouched and no
// repair call may be issued.
func TestProxy_StrictJSON_MasterSwitchOff(t *testing.T) {
	var repairCalls int32

	fenced := "```json\n{\"a\":1}\n```"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "repair engine") {
			atomic.AddInt32(&repairCalls, 1)
		}

		w.Header().Set("Content-Type", "application/json")
		payload := map[string]any{
			"choices": []any{
				map[string]any{
					"index":         0,
					"message":       map[string]any{"role": "assistant", "content": fenced},
					"finish_reason": "stop",
				},
			},
		}
		out, _ := json.Marshal(payload)
		_, _ = w.Write(out)
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = upstream.URL
	cfg.Contract.StrictJSONEnabled = false
	h := newTestHandler(t, cfg)

	rec := postChatCompletion(t, h, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"json"}],"stream":false,"response_format":{"type":"json_object"}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&repairCalls); got != 0 {
		t.Fatalf("expected no repair calls when strict JSON is disabled, got %d", got)
	}
	if !strings.Contains(rec.Body.String(), "```json") {
		t.Fatalf("expected fenced content to be forwarded untouched, got: %s", rec.Body.String())
	}
}

// TestProxy_StrictJSON_StripsFences proves the enabled path still works and
// that re-encoding keeps integer literals intact (no float64 scientific notation).
func TestProxy_StrictJSON_StripsFences(t *testing.T) {
	fenced := "```json\n{\"ok\":true}\n```"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1750000000,"choices":[{"index":0,"message":{"role":"assistant","content":` +
			mustJSONString(fenced) + `},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = upstream.URL
	h := newTestHandler(t, cfg)

	rec := postChatCompletion(t, h, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"json"}],"stream":false,"response_format":{"type":"json_object"}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var parsed struct {
		Created int64 `json:"created"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("client response is not valid JSON: %v (%s)", err, rec.Body.String())
	}
	if parsed.Created != 1750000000 {
		t.Fatalf("created literal was reformatted: %s", rec.Body.String())
	}
	if got := parsed.Choices[0].Message.Content; got != `{"ok":true}` {
		t.Fatalf("expected fences stripped, got %q", got)
	}
}

// TestProxy_FallbackPreservesLogicalModel verifies that when the local tier
// fails after rewriting the outbound model field (e.g. "coding" -> "qwen2.5-coder:7b"),
// cloud fallback still resolves from the client's original logical model ("coding" -> "deepseek-coder")
// rather than from the mutated local physical model name.
func TestProxy_FallbackPreservesLogicalModel(t *testing.T) {
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer localServer.Close()

	var cloudReceivedModel string
	cloudServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		cloudReceivedModel, _ = body["model"].(string)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer cloudServer.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = localServer.URL
	cfg.Local.ModelMapping = map[string]string{
		"coding": "qwen2.5-coder:7b",
	}
	cfg.Cloud.Endpoint = cloudServer.URL
	cfg.Cloud.ModelMapping = map[string]string{
		"coding":  "deepseek-coder",
		"default": "gpt-4o-mini",
	}

	h := newTestHandler(t, cfg)

	rec := postChatCompletion(t, h, `{"model":"coding","messages":[{"role":"user","content":"hi"}],"stream":false}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if cloudReceivedModel != "deepseek-coder" {
		t.Fatalf("expected cloud tier to receive mapped model 'deepseek-coder', got %q (logical model was corrupted by in-place local rewrite)", cloudReceivedModel)
	}
}

// mustJSONString encodes s as a JSON string literal (without surrounding quotes
// being added twice) for embedding into a hand-written payload.
func mustJSONString(s string) string {
	out, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(out)
}
