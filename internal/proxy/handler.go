// Package proxy implements OpenAI-compatible HTTP and SSE governance handlers for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/patchcat-dev/edgecat/internal/audit"
	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/contract"
	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/router"
)

// defaultStreamIdleTimeoutMs bounds how long an SSE stream may stay silent
// before the connection write deadline expires.
const defaultStreamIdleTimeoutMs = 300000

// Handler orchestrates request lifecycle, filtering, routing, and auditing.
type Handler struct {
	cfg        *config.Config
	masker     *filter.Masker
	router     *router.Router
	guard      *contract.Guard
	audit      *audit.Logger
	httpClient *http.Client
}

// NewHandler creates a new EdgeCat proxy handler.
func NewHandler(
	cfg *config.Config,
	masker *filter.Masker,
	r *router.Router,
	g *contract.Guard,
	a *audit.Logger,
) *Handler {
	client := &http.Client{
		Timeout: 0, // Individual request contexts manage timeouts
	}
	return &Handler{
		cfg:        cfg,
		masker:     masker,
		router:     r,
		guard:      g,
		audit:      a,
		httpClient: client,
	}
}

// ServeHTTP handles /v1/chat/completions, /health, and /v1/models.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/health":
		h.handleHealth(w, r)
	case r.URL.Path == "/v1/models" && r.Method == http.MethodGet:
		h.handleModels(w, r)
	case r.URL.Path == "/v1/chat/completions" && r.Method == http.MethodPost:
		h.handleChatCompletions(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status": "healthy",
		"local_tier": map[string]any{
			"configured":         h.cfg.Local.Endpoint != "",
			"endpoint":           h.cfg.Local.Endpoint,
			"active_concurrency": h.router.CurrentLocalConcurrency(),
			"max_concurrency":    h.router.MaxLocalConcurrency(),
			"fallbacks_total":    h.router.TotalFallbacks(),
		},
		"cloud_tier": map[string]any{
			"configured": h.cfg.Cloud.Endpoint != "",
			"endpoint":   h.cfg.Cloud.Endpoint,
		},
		"audit": map[string]any{
			"written_total": h.audit.WrittenCount(),
			"dropped_total": h.audit.DroppedCount(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleModels(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"object": "list",
		"data": []map[string]any{
			{"id": "default", "object": "model", "owned_by": "edgecat"},
			{"id": "gpt-4o-mini", "object": "model", "owned_by": "edgecat"},
			{"id": "qwen2.5:7b", "object": "model", "owned_by": "edgecat"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	requestID := generateRequestID()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error": "failed to read request body"}`, http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	req, err := ParseRequest(bodyBytes)
	if err != nil {
		http.Error(w, `{"error": "malformed JSON request body"}`, http.StatusBadRequest)
		return
	}

	// 1. PII Masking and Request Vault
	vault := filter.NewVault()
	if h.cfg.Filter.Enabled && h.masker != nil {
		MaskRequestContent(req, h.masker, vault)
	}
	piiRedacted := vault.RedactedCount()

	// 2. Routing and concurrency admission
	decision := h.router.DecideRoute(req.Model())
	defer func() {
		if decision.AcquiredLocal {
			h.router.ReleaseLocal()
			decision.AcquiredLocal = false
		}
	}()

	// 3. Strict JSON contract opt-in.
	// contract.strict_json_enabled is the master switch; the client may then ask
	// for enforcement per call. Contract repair requires buffering the entire
	// response, so it deliberately does not apply to SSE streams (documented in
	// README: streaming keeps its first-token latency instead).
	strictJSON := h.guard.StrictJSONEnabled && clientWantsStrictJSON(r, req)

	if req.Stream() {
		h.handleStreaming(w, r, requestID, req, decision, vault, startTime, piiRedacted)
	} else {
		h.handleNonStreaming(w, r, requestID, req, decision, vault, startTime, piiRedacted, strictJSON)
	}
}

// clientWantsStrictJSON reports whether this specific call opted into contract
// enforcement, via header or response_format.
func clientWantsStrictJSON(r *http.Request, req *Request) bool {
	if strings.EqualFold(r.Header.Get("X-EdgeCat-Strict-JSON"), "true") {
		return true
	}
	return req.ResponseFormatType() == "json_object"
}

func (h *Handler) handleStreaming(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	req *Request,
	decision router.Decision,
	vault *filter.Vault,
	startTime time.Time,
	piiRedacted int,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error": "streaming unsupported by client"}`, http.StatusInternalServerError)
		return
	}

	// SSE responses routinely outlive the server-wide WriteTimeout: a slow local
	// model can legitimately stream for minutes. Disabling the deadline outright
	// would let a dead peer pin a goroutine forever, so instead we install a
	// rolling idle deadline that is refreshed on every successful flush.
	touchDeadline := newStreamDeadlineRefresher(w, h.cfg.Server.StreamIdleTimeoutMs)

	var upstreamResp *http.Response
	var finalTarget = decision.Target
	var finalModel = decision.TargetModel
	var ttftMs int64 = 0
	var firstChunk []byte

	// If Local was acquired, attempt local streaming with strict TTFT timeout watcher
	if decision.AcquiredLocal {
		resp, chunk, capturedTTFT, cancelLocal, err := h.tryLocalStream(r.Context(), req, decision.TargetModel)
		if err == nil {
			// The local stream must stay alive until the body is fully relayed,
			// so cancellation is deferred to the end of this handler.
			defer cancelLocal()
			upstreamResp = resp
			firstChunk = chunk
			ttftMs = capturedTTFT
		} else {
			// Local failed or TTFT timed out! Trigger fallback to Cloud tier
			log.Printf("[Proxy %s] Local streaming fallback (%v). Rerouting to Cloud tier.", reqID, err)
			h.router.ReleaseLocal()
			decision.AcquiredLocal = false
			h.router.RecordFallback()

			finalTarget = router.TargetCloud
			finalModel = h.router.ResolveModel(router.TargetCloud, req.Model())
		}
	}

	// If not routed to local or local timed out, route to Cloud
	if upstreamResp == nil {
		cloudResp, err := h.callCloudStream(r.Context(), req, finalModel)
		if err != nil {
			log.Printf("[Proxy %s] Cloud fallback error: %v", reqID, err)
			http.Error(w, fmt.Sprintf(`{"error": "inference tier failed: %s"}`, err.Error()), http.StatusBadGateway)
			h.audit.Log(&audit.Record{
				RequestID:        reqID,
				RouteTarget:      finalTarget,
				Model:            finalModel,
				LatencyMs:        time.Since(startTime).Milliseconds(),
				TTFTMs:           0,
				PIIRedactedCount: piiRedacted,
				Status:           http.StatusBadGateway,
				CreatedAt:        startTime,
			})
			return
		}
		upstreamResp = cloudResp
	}
	defer upstreamResp.Body.Close()

	// Write SSE Response Headers
	touchDeadline()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-EdgeCat-Route", finalTarget)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	rehydrator := filter.NewSlidingRehydrator(vault)

	// Process first chunk if already read during TTFT watcher
	if len(firstChunk) > 0 {
		out := rehydrator.Feed(string(firstChunk))
		if len(out) > 0 {
			touchDeadline()
			_, _ = w.Write([]byte(out))
			flusher.Flush()
		}
	}

	// Stream remainder
	buf := make([]byte, 4096)
	for {
		n, readErr := upstreamResp.Body.Read(buf)
		if n > 0 {
			if ttftMs == 0 {
				ttftMs = time.Since(startTime).Milliseconds()
			}
			out := rehydrator.Feed(string(buf[:n]))
			if len(out) > 0 {
				touchDeadline()
				_, _ = w.Write([]byte(out))
				flusher.Flush()
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			break
		}
	}

	// Flush any pending tail in rehydrator buffer
	if tail := rehydrator.Flush(); len(tail) > 0 {
		touchDeadline()
		_, _ = w.Write([]byte(tail))
		flusher.Flush()
	}

	// Log audit record asynchronously
	h.audit.Log(&audit.Record{
		RequestID:        reqID,
		RouteTarget:      finalTarget,
		Model:            finalModel,
		LatencyMs:        time.Since(startTime).Milliseconds(),
		TTFTMs:           ttftMs,
		PIIRedactedCount: piiRedacted,
		Status:           http.StatusOK,
		CreatedAt:        startTime,
	})
}

// newStreamDeadlineRefresher returns a function that pushes the connection write
// deadline forward. Callers invoke it before every write/flush so that a
// long-lived stream is bounded by idleness rather than by total duration.
//
// http.ResponseController reports ErrNotSupported for recorders and custom
// ResponseWriters; the error is intentionally ignored so the handler stays
// usable in tests and behind middleware that does not expose deadlines.
func newStreamDeadlineRefresher(w http.ResponseWriter, idleTimeoutMs int) func() {
	if idleTimeoutMs <= 0 {
		idleTimeoutMs = defaultStreamIdleTimeoutMs
	}
	idle := time.Duration(idleTimeoutMs) * time.Millisecond
	rc := http.NewResponseController(w)

	touch := func() {
		_ = rc.SetWriteDeadline(time.Now().Add(idle))
	}
	touch()
	return touch
}

// tryLocalStream attempts to initiate a stream with the local tier within ttft_timeout_ms.
// The TTFT timer starts immediately and covers connection, headers, and the first body byte.
//
// On success it also returns the cancel func for the local context. Ownership is
// handed to the caller because the local stream must outlive this call: the
// caller cancels once the response body has been fully consumed.
func (h *Handler) tryLocalStream(
	ctx context.Context,
	req *Request,
	targetModel string,
) (*http.Response, []byte, int64, context.CancelFunc, error) {
	req.SetModel(targetModel)
	payload, err := req.Marshal()
	if err != nil {
		return nil, nil, 0, nil, err
	}

	ttftTimeout := h.router.LocalTTFTTimeout()
	ttftTimer := time.NewTimer(ttftTimeout)
	defer ttftTimer.Stop()

	localCtx, localCancel := context.WithCancel(ctx)

	url := strings.TrimRight(h.router.LocalEndpoint(), "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(localCtx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		localCancel()
		return nil, nil, 0, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey := h.router.LocalAPIKey(); apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	start := time.Now()

	type doResult struct {
		resp *http.Response
		err  error
	}
	doChan := make(chan doResult, 1)
	go func() {
		r, doErr := h.httpClient.Do(httpReq)
		doChan <- doResult{resp: r, err: doErr}
	}()

	var resp *http.Response
	select {
	case <-ttftTimer.C:
		localCancel()
		return nil, nil, 0, nil, fmt.Errorf("local TTFT timed out (%v) waiting for response headers", ttftTimeout)
	case <-ctx.Done():
		localCancel()
		return nil, nil, 0, nil, ctx.Err()
	case res := <-doChan:
		if res.err != nil {
			localCancel()
			return nil, nil, 0, nil, fmt.Errorf("local connection failed: %w", res.err)
		}
		resp = res.resp
	}

	if resp.StatusCode >= 400 {
		resp.Body.Close()
		localCancel()
		return nil, nil, 0, nil, fmt.Errorf("local returned status %d", resp.StatusCode)
	}

	// Wait for the first non-empty byte/chunk before TTFT timer expires
	type readResult struct {
		data []byte
		err  error
	}
	readChan := make(chan readResult, 1)
	buf := make([]byte, 4096)
	go func() {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			readChan <- readResult{data: buf[:n], err: rErr}
		} else {
			readChan <- readResult{data: nil, err: rErr}
		}
	}()

	select {
	case <-ttftTimer.C:
		resp.Body.Close()
		localCancel()
		return nil, nil, 0, nil, fmt.Errorf("local TTFT timed out (%v) waiting for first chunk", ttftTimeout)
	case <-ctx.Done():
		resp.Body.Close()
		localCancel()
		return nil, nil, 0, nil, ctx.Err()
	case rRes := <-readChan:
		if rRes.err != nil && len(rRes.data) == 0 {
			resp.Body.Close()
			localCancel()
			return nil, nil, 0, nil, fmt.Errorf("local stream read error: %w", rRes.err)
		}
		// First chunk received successfully within TTFT timeout
		ttftTimer.Stop()
		ttft := time.Since(start).Milliseconds()
		return resp, rRes.data, ttft, localCancel, nil
	}
}

// callCloudStream connects to the cloud fallback tier for streaming.
func (h *Handler) callCloudStream(
	ctx context.Context,
	req *Request,
	targetModel string,
) (*http.Response, error) {
	req.SetModel(targetModel)
	payload, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(h.router.CloudEndpoint(), "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey := h.router.CloudAPIKey(); apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("cloud tier returned status %d: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}

func (h *Handler) handleNonStreaming(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	req *Request,
	decision router.Decision,
	vault *filter.Vault,
	startTime time.Time,
	piiRedacted int,
	strictJSON bool,
) {
	var finalTarget = decision.Target
	var finalModel = decision.TargetModel
	var rawResp []byte
	var err error

	// If Local was acquired, attempt call with TTFT/timeout
	if decision.AcquiredLocal {
		rawResp, err = h.callLocalNonStreaming(r.Context(), req, decision.TargetModel)
		if err != nil {
			log.Printf("[Proxy %s] Local non-streaming fallback: %v. Rerouting to Cloud.", reqID, err)
			h.router.ReleaseLocal()
			decision.AcquiredLocal = false
			h.router.RecordFallback()

			finalTarget = router.TargetCloud
			finalModel = h.router.ResolveModel(router.TargetCloud, req.Model())
		}
	}

	// Route to Cloud if local not used or fallback triggered
	if len(rawResp) == 0 {
		rawResp, err = h.callCloudNonStreaming(r.Context(), req, finalModel)
		if err != nil {
			log.Printf("[Proxy %s] Cloud non-streaming error: %v", reqID, err)
			http.Error(w, fmt.Sprintf(`{"error": "inference tier failed: %s"}`, err.Error()), http.StatusBadGateway)
			h.audit.Log(&audit.Record{
				RequestID:        reqID,
				RouteTarget:      finalTarget,
				Model:            finalModel,
				LatencyMs:        time.Since(startTime).Milliseconds(),
				TTFTMs:           0,
				PIIRedactedCount: piiRedacted,
				Status:           http.StatusBadGateway,
				CreatedAt:        startTime,
			})
			return
		}
	}

	// 3. Contract Strict JSON Enforcement & Single Repair Loop
	if strictJSON {
		rawResp = h.enforceStrictJSON(r.Context(), reqID, finalTarget, finalModel, rawResp)
	}

	// 4. Rehydrate Vault Placeholders on the raw payload.
	// Re-encoding through typed structs here would silently strip tool_calls,
	// reasoning_content and every vendor extension the upstream returned.
	outBytes := RehydrateBody(vault, rawResp)

	latencyMs := time.Since(startTime).Milliseconds()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-EdgeCat-Route", finalTarget)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outBytes)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(outBytes)

	// Async SQLite audit
	h.audit.Log(&audit.Record{
		RequestID:        reqID,
		RouteTarget:      finalTarget,
		Model:            finalModel,
		LatencyMs:        latencyMs,
		TTFTMs:           0, // whole-body responses have no first-token latency
		PIIRedactedCount: piiRedacted,
		Status:           http.StatusOK,
		CreatedAt:        startTime,
	})
}

// enforceStrictJSON strips code fences from choices[0].message.content and
// triggers at most one bounded repair call. It only rewrites that single field
// and returns the payload untouched on any structural surprise, so unknown
// response fields survive the round trip.
func (h *Handler) enforceStrictJSON(
	ctx context.Context,
	reqID, target, model string,
	raw []byte,
) []byte {
	obj, ok := decodeObject(raw)
	if !ok {
		return raw
	}
	content, ok := firstChoiceContent(obj)
	if !ok {
		return raw
	}

	repaired, _, guardErr := h.guard.EnforceAndRepair(ctx, content, func(callCtx context.Context, broken string) (string, error) {
		return h.invokeRepair(callCtx, target, model, broken)
	})
	if guardErr != nil {
		log.Printf("[Proxy %s] Strict JSON enforcement warning: %v", reqID, guardErr)
		return raw
	}
	if !setFirstChoiceContent(obj, repaired) {
		return raw
	}

	out, err := marshalObject(obj)
	if err != nil {
		log.Printf("[Proxy %s] Strict JSON re-encode failed: %v", reqID, err)
		return raw
	}
	return out
}

func (h *Handler) callLocalNonStreaming(
	ctx context.Context,
	req *Request,
	targetModel string,
) ([]byte, error) {
	req.SetModel(targetModel)
	payload, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	timeout := h.router.LocalTTFTTimeout() * 3
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := strings.TrimRight(h.router.LocalEndpoint(), "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey := h.router.LocalAPIKey(); apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("local returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("local returned empty body")
	}
	return body, nil
}

func (h *Handler) callCloudNonStreaming(
	ctx context.Context,
	req *Request,
	targetModel string,
) ([]byte, error) {
	req.SetModel(targetModel)
	payload, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	callCtx, cancel := context.WithTimeout(ctx, h.router.CloudTimeout())
	defer cancel()

	url := strings.TrimRight(h.router.CloudEndpoint(), "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey := h.router.CloudAPIKey(); apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cloud returned status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// invokeRepair executes a single repair prompt using the active inference tier.
func (h *Handler) invokeRepair(
	ctx context.Context,
	target, model, broken string,
) (string, error) {
	repairReq := newRepairRequest(model, broken)

	var data []byte
	var err error
	if target == router.TargetLocal {
		data, err = h.callLocalNonStreaming(ctx, repairReq, model)
	} else {
		data, err = h.callCloudNonStreaming(ctx, repairReq, model)
	}
	if err != nil {
		return "", err
	}

	obj, ok := decodeObject(data)
	if !ok {
		return "", errors.New("repair response is not a JSON object")
	}
	content, ok := firstChoiceContent(obj)
	if !ok {
		return "", errors.New("empty repair response")
	}
	return content, nil
}

func generateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "ec_" + hex.EncodeToString(b)
}
