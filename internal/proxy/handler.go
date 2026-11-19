// Package proxy implements OpenAI-compatible HTTP and SSE governance handlers for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patchcat-dev/edgecat/internal/audit"
	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/contract"
	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/quota"
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
	quotaMgr   *quota.Manager
	httpClient *http.Client

	mutatorMu sync.RWMutex
	mutators  []RequestMutator
}

// NewHandler creates a new EdgeCat proxy handler.
func NewHandler(
	cfg *config.Config,
	masker *filter.Masker,
	r *router.Router,
	g *contract.Guard,
	a *audit.Logger,
	qm *quota.Manager,
	opts ...HandlerOption,
) *Handler {
	client := &http.Client{
		Timeout: 0, // Individual request contexts manage timeouts
	}
	h := &Handler{
		cfg:        cfg,
		masker:     masker,
		router:     r,
		guard:      g,
		audit:      a,
		quotaMgr:   qm,
		httpClient: client,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
	return h
}

// UseMutator registers one or more two-stage RequestMutator hooks.
// Nil mutators are ignored. Safe for concurrent registration and inspection.
func (h *Handler) UseMutator(mutators ...RequestMutator) {
	h.mutatorMu.Lock()
	defer h.mutatorMu.Unlock()
	for _, m := range mutators {
		if m != nil {
			h.mutators = append(h.mutators, m)
		}
	}
}

// MutatorNames returns the names of all registered RequestMutators in execution order.
func (h *Handler) MutatorNames() []string {
	snap := h.mutatorSnapshot()
	names := make([]string, len(snap))
	for i, m := range snap {
		names[i] = m.Name()
	}
	return names
}

func (h *Handler) mutatorSnapshot() []RequestMutator {
	h.mutatorMu.RLock()
	defer h.mutatorMu.RUnlock()
	if len(h.mutators) == 0 {
		return nil
	}
	out := make([]RequestMutator, len(h.mutators))
	copy(out, h.mutators)
	return out
}

// ServeHTTP handles /v1/chat/completions, /health, and /v1/models.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle CORS & Chrome Private Network Access preflights
	if h.handleCORS(w, r) {
		return
	}

	// /health is public for liveness checks (does not leak sensitive configs)
	if r.URL.Path == "/health" {
		h.handleHealth(w, r)
		return
	}

	// Validate client auth token if enabled
	client, authed := h.authenticate(r)
	if !authed {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid_request_error", "invalid_api_key", "unauthorized: valid Bearer token required in Authorization header")
		return
	}

	switch {
	case (r.URL.Path == "/admin/status" || r.URL.Path == "/v1/admin/status") && r.Method == http.MethodGet:
		h.handleAdminStatus(w, r)
	case r.URL.Path == "/v1/models" && r.Method == http.MethodGet:
		h.handleModels(w, r)
	case r.URL.Path == "/v1/chat/completions" && r.Method == http.MethodPost:
		h.handleChatCompletions(w, r, client)
	default:
		http.NotFound(w, r)
	}
}

// handleCORS sets CORS headers and handles OPTIONS preflights including Chrome PNA.
// It returns true if the request was an OPTIONS preflight and has been fully served.
// By default (empty AllowedOrigins), cross-origin requests are denied (secure fail-closed).
func (h *Handler) handleCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		return false
	}

	allowed := false
	for _, o := range h.cfg.Server.AllowedOrigins {
		if o == "*" || strings.EqualFold(o, origin) {
			allowed = true
			break
		}
	}

	if !allowed {
		log.Printf("[CORS] Rejected origin: %q", origin)
		writeOpenAIError(w, http.StatusForbidden, "invalid_request_error", "origin_not_allowed", "CORS origin not allowed")
		return true
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-EdgeCat-Strict-JSON, Access-Control-Request-Private-Network")
	w.Header().Set("Access-Control-Expose-Headers", "X-EdgeCat-Route, Content-Length")
	w.Header().Set("Access-Control-Max-Age", "86400")

	// Chrome Private Network Access (PNA) preflight support
	if strings.EqualFold(r.Header.Get("Access-Control-Request-Private-Network"), "true") {
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
	}

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// authenticate validates the Authorization: Bearer <token> header against configured clients.
func (h *Handler) authenticate(r *http.Request) (*config.ClientConfig, bool) {
	if !h.cfg.Auth.Enabled {
		// Anonymous client when auth is disabled
		return &config.ClientConfig{Name: "anonymous"}, true
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return nil, false
	}
	rawToken := strings.TrimSpace(authHeader[7:])
	if rawToken == "" {
		return nil, false
	}

	for _, c := range h.cfg.Auth.Clients {
		if subtle.ConstantTimeCompare([]byte(c.Token), []byte(rawToken)) == 1 {
			return &c, true
		}
	}
	return nil, false
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Public minimal liveness check. Does not expose internal endpoints, client identities, or quotas.
	resp := map[string]any{
		"status": "healthy",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	breakerState, breakerFailures := h.router.BreakerState()

	// Detailed operational status for authenticated administrative inspection.
	resp := map[string]any{
		"status": "healthy",
		"local_tier": map[string]any{
			"configured":         h.cfg.Local.Endpoint != "",
			"endpoint":           h.cfg.Local.Endpoint,
			"active_concurrency": h.router.CurrentLocalConcurrency(),
			"max_concurrency":    h.router.MaxLocalConcurrency(),
			"fallbacks_total":    h.router.TotalFallbacks(),
			"circuit_breaker": map[string]any{
				"state":                breakerState,
				"consecutive_failures": breakerFailures,
			},
		},
		"cloud_tier": map[string]any{
			"configured": h.cfg.Cloud.Endpoint != "",
			"endpoint":   h.cfg.Cloud.Endpoint,
		},
		"audit": map[string]any{
			"written_total": h.audit.WrittenCount(),
			"dropped_total": h.audit.DroppedCount(),
		},
		"mutators": h.MutatorNames(),
	}

	if h.quotaMgr != nil {
		resp["clients_usage"] = h.quotaMgr.ClientUsageSummary()
		resp["next_quota_reset"] = h.quotaMgr.NextResetTime().Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleModels(w http.ResponseWriter, r *http.Request) {
	// D5: Dynamically derive logical model IDs from local and cloud mappings.
	// Physical model names (such as "qwen2.5:7b" or local paths) are never leaked.
	modelSet := make(map[string]struct{})
	modelSet["default"] = struct{}{}

	if h.cfg.Local.ModelMapping != nil {
		for logical := range h.cfg.Local.ModelMapping {
			if logical != "" {
				modelSet[logical] = struct{}{}
			}
		}
	}
	if h.cfg.Cloud.ModelMapping != nil {
		for logical := range h.cfg.Cloud.ModelMapping {
			if logical != "" {
				modelSet[logical] = struct{}{}
			}
		}
	}

	modelList := make([]string, 0, len(modelSet))
	for m := range modelSet {
		modelList = append(modelList, m)
	}
	sort.Strings(modelList)

	data := make([]map[string]any, 0, len(modelList))
	for _, m := range modelList {
		data = append(data, map[string]any{
			"id":       m,
			"object":   "model",
			"owned_by": "edgecat",
		})
	}

	resp := map[string]any{
		"object": "list",
		"data":   data,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleChatCompletions(w http.ResponseWriter, r *http.Request, client *config.ClientConfig) {
	// Enforce Content-Type: application/json (RFC 7231 / OpenAI specification)
	ct := r.Header.Get("Content-Type")
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	if mediaType != "application/json" {
		writeOpenAIError(w, http.StatusUnsupportedMediaType, "invalid_request_error", "unsupported_media_type", "unsupported media type: Content-Type must be application/json")
		return
	}

	startTime := time.Now()
	requestID := generateRequestID()

	maxBytes := h.cfg.Server.MaxRequestBodyBytes
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "payload_too_large", fmt.Sprintf("request body exceeds limit of %d bytes", maxBytes))
			return
		}
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "invalid_body", "failed to read request body")
		return
	}
	_ = r.Body.Close()

	req, err := ParseRequest(bodyBytes)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "malformed_json", "malformed JSON request body")
		return
	}

	clientName := "anonymous"
	piiPolicy := h.cfg.Filter.Policy
	queueWaitMs := h.cfg.Local.QueueWaitMs
	if client != nil {
		clientName = clientNameOf(client.Name)
		if client.PIIPolicy != "" {
			piiPolicy = client.PIIPolicy
		}
		if client.QueueWaitMs > 0 {
			queueWaitMs = client.QueueWaitMs
		}
	}
	if piiPolicy == "" {
		piiPolicy = "mask_always"
	}

	// 0. Stage 1 RequestMutators (Pre-Mask: runs before PII policy evaluation and masking)
	mutators := h.mutatorSnapshot()
	var meta *RequestMeta
	localOnly := false
	if len(mutators) > 0 {
		meta = &RequestMeta{
			RequestID:   requestID,
			ClientName:  clientName,
			HTTPHeader:  r.Header.Clone(),
			Stage:       StagePreMask,
			PIIPolicy:   piiPolicy,
			LocalOnly:   localOnly,
			QueueWaitMs: queueWaitMs,
			Values:      make(map[string]any),
		}
		for _, m := range mutators {
			if err := m.MutatePreMask(r.Context(), req, meta); err != nil {
				h.handleMutatorError(w, requestID, clientName, req.Model(), startTime, 0, StagePreMask, m.Name(), err)
				return
			}
		}
		piiPolicy = normalizePIIPolicy(meta.PIIPolicy)
		localOnly = meta.LocalOnly
		queueWaitMs = meta.QueueWaitMs
	}

	// 1. PII Policy Evaluation & Eager Masking (when policy == mask_always)
	vault := filter.NewVault()
	if h.cfg.Filter.Enabled && h.masker != nil {
		switch piiPolicy {
		case "block":
			if RequestContainsPII(req, h.masker) {
				writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "pii_blocked", "request contains sensitive PII blocked by policy")
				h.recordAudit(requestID, clientName, "blocked", req.Model(), startTime, 0, 0, http.StatusBadRequest)
				return
			}
		case "local_only":
			if RequestContainsPII(req, h.masker) {
				localOnly = true
			}
		case "mask_on_egress":
			// Defer masking until dispatch confirms cloud routing/fallback.
		default: // "mask_always"
			MaskRequestContent(req, h.masker, vault)
		}
	}

	// 1.5 Stage 2 RequestMutators (Post-Mask: runs after PII policy/masking, before routing)
	if len(mutators) > 0 {
		meta.Stage = StagePostMask
		meta.PIIPolicy = piiPolicy
		meta.LocalOnly = localOnly
		meta.QueueWaitMs = queueWaitMs
		meta.PIIRedactedCount = vault.RedactedCount()
		for _, m := range mutators {
			if err := m.MutatePostMask(r.Context(), req, meta); err != nil {
				h.handleMutatorError(w, requestID, clientName, req.Model(), startTime, vault.RedactedCount(), StagePostMask, m.Name(), err)
				return
			}
		}
		// Security invariant: once PII policy enforces localOnly=true, a post-mask
		// mutator may tighten routing to localOnly=true, never downgrade it to false.
		localOnly = localOnly || meta.LocalOnly
		queueWaitMs = meta.QueueWaitMs
	}

	// 2. Routing and concurrency admission (with optional queue_wait_ms)
	decision := h.router.DecideRouteWithContext(r.Context(), req.Model(), queueWaitMs)
	defer func() {
		if decision.AcquiredLocal {
			h.router.ReleaseLocal()
			decision.AcquiredLocal = false
		}
	}()

	if localOnly && !decision.AcquiredLocal {
		writeOpenAIError(w, http.StatusServiceUnavailable, "service_unavailable_error", "pii_local_only_unavailable", "request contains PII restricted to local inference, and local tier is unavailable")
		h.recordAudit(requestID, clientName, router.TargetLocal, req.Model(), startTime, 0, 0, http.StatusServiceUnavailable)
		return
	}

	// 3. Strict JSON contract opt-in.
	// contract.strict_json_enabled is the master switch; the client may then ask
	// for enforcement per call. Contract repair requires buffering the entire
	// response, so it deliberately does not apply to SSE streams (documented in
	// README: streaming keeps its first-token latency instead).
	strictJSON := h.guard.StrictJSONEnabled && clientWantsStrictJSON(r, req)

	if req.Stream() {
		h.handleStreaming(w, r, requestID, req, &decision, vault, startTime, clientName, piiPolicy, localOnly)
	} else {
		h.handleNonStreaming(w, r, requestID, req, &decision, vault, startTime, strictJSON, clientName, piiPolicy, localOnly)
	}
}

func normalizePIIPolicy(policy string) string {
	switch policy {
	case "mask_always", "mask_on_egress", "local_only", "block":
		return policy
	default:
		return "mask_always"
	}
}

func (h *Handler) handleMutatorError(
	w http.ResponseWriter,
	reqID string,
	clientName string,
	model string,
	startTime time.Time,
	piiRedacted int,
	stage MutationStage,
	mutatorName string,
	err error,
) {
	statusCode := http.StatusBadRequest
	errType := "invalid_request_error"
	errCode := "mutator_rejected"
	errMsg := err.Error()

	var mErr *MutatorError
	if errors.As(err, &mErr) {
		if mErr.StatusCode > 0 {
			statusCode = mErr.StatusCode
		}
		if mErr.Type != "" {
			errType = mErr.Type
		}
		if mErr.Code != "" {
			errCode = mErr.Code
		}
		errMsg = mErr.Error()
	}

	log.Printf("[Proxy %s] Mutator %q rejected request at stage %s: %v", reqID, mutatorName, stage, err)
	writeOpenAIError(w, statusCode, errType, errCode, errMsg)
	h.recordAudit(reqID, clientName, "blocked", model, startTime, 0, piiRedacted, statusCode)
}

func (h *Handler) recordAudit(reqID, clientName, target, model string, startTime time.Time, ttftMs int64, piiRedacted, status int) {
	h.audit.Log(&audit.Record{
		RequestID:        reqID,
		ClientName:       clientNameOf(clientName),
		RouteTarget:      target,
		Model:            model,
		LatencyMs:        time.Since(startTime).Milliseconds(),
		TTFTMs:           ttftMs,
		PIIRedactedCount: piiRedacted,
		Status:           status,
		CreatedAt:        startTime,
	})
}

// checkCloudQuota enforces daily cloud limits in the pre-WriteHeader window.
func (h *Handler) checkCloudQuota(w http.ResponseWriter, clientName string) bool {
	if h.quotaMgr == nil {
		return true
	}
	status := h.quotaMgr.CheckAndIncrementCloud(clientName)
	if status == quota.StatusLocalOnlyDisallowed {
		writeOpenAIError(w, http.StatusServiceUnavailable, "service_unavailable_error", "cloud_fallback_disabled", "local tier unavailable and cloud fallback is disallowed for client")
		return false
	}
	if status == quota.StatusQuotaExceeded {
		writeOpenAIError(w, http.StatusTooManyRequests, "insufficient_quota", "daily_cloud_limit_exceeded", "daily cloud fallback quota exceeded for client")
		return false
	}
	return true
}

// classifyLocalError maps a local-tier failure to a circuit-breaker outcome.
// Client disconnects are neutral; 4xx responses prove the local server is alive.
func classifyLocalError(ctx context.Context, err error) router.Outcome {
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return router.OutcomeNeutral
	}
	var stErr *upstreamStatusError
	if errors.As(err, &stErr) && stErr.code >= 400 && stErr.code < 500 {
		return router.OutcomeSuccess
	}
	return router.OutcomeFailure
}

// clientWantsStrictJSON reports whether this specific call opted into contract
// enforcement, via header or response_format.
func clientWantsStrictJSON(r *http.Request, req *Request) bool {
	if strings.EqualFold(r.Header.Get("X-EdgeCat-Strict-JSON"), "true") {
		return true
	}
	rf := req.ResponseFormatType()
	return rf == "json_object" || rf == "json_schema"
}

type dispatchResult struct {
	target      string
	model       string
	ttftMs      int64
	piiRedacted int
	usingLocal  bool
	resp        *http.Response
	firstChunk  []byte
	cancel      context.CancelFunc
	rawBody     []byte
	handled     bool
}

// dispatch executes the local-first admission, TTFT fallback, egress PII masking,
// cloud quota check, and upstream invocation shared by streaming and non-streaming paths.
func (h *Handler) dispatch(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	req *Request,
	decision *router.Decision,
	vault *filter.Vault,
	startTime time.Time,
	clientName string,
	piiPolicy string,
	localOnly bool,
	forceLocalStream bool,
) dispatchResult {
	res := dispatchResult{
		target:      decision.Target,
		model:       decision.TargetModel,
		piiRedacted: vault.RedactedCount(),
	}

	if decision.AcquiredLocal {
		var prevStreamOpts any
		var hadStreamOpts bool
		if forceLocalStream {
			req.fields["stream"] = true
			prevStreamOpts, hadStreamOpts = req.fields["stream_options"]
			if !hadStreamOpts {
				req.fields["stream_options"] = map[string]any{"include_usage": true}
			}
		}

		resp, chunk, capturedTTFT, cancelLocal, err := h.tryLocalStream(r.Context(), req, decision.TargetModel)

		if forceLocalStream {
			req.fields["stream"] = false
			if hadStreamOpts {
				req.fields["stream_options"] = prevStreamOpts
			} else {
				delete(req.fields, "stream_options")
			}
		}

		if err == nil {
			res.usingLocal = true
			res.resp = resp
			res.firstChunk = chunk
			res.ttftMs = capturedTTFT
			res.cancel = cancelLocal
			return res
		}

		outcome := classifyLocalError(r.Context(), err)
		h.router.RecordLocalOutcome(outcome)
		h.router.ReleaseLocal()
		decision.AcquiredLocal = false

		if outcome == router.OutcomeNeutral {
			h.recordAudit(reqID, clientName, res.target, res.model, startTime, 0, res.piiRedacted, StatusClientClosedRequest)
			res.handled = true
			return res
		}

		if localOnly {
			log.Printf("[Proxy %s] Local failed (%v) and PII policy is local_only; blocking cloud fallback.", reqID, err)
			writeOpenAIError(w, http.StatusServiceUnavailable, "service_unavailable_error", "pii_local_only_unavailable", "local inference failed and PII local_only policy forbids cloud fallback")
			h.recordAudit(reqID, clientName, res.target, res.model, startTime, 0, res.piiRedacted, http.StatusServiceUnavailable)
			res.handled = true
			return res
		}

		log.Printf("[Proxy %s] Local fallback (%v). Rerouting to Cloud tier.", reqID, err)
		h.router.RecordFallback()
		res.target = router.TargetCloud
		res.model = h.router.ResolveModel(router.TargetCloud, req.Model())
	}

	// Apply egress masking only when routing/falling back to cloud under mask_on_egress.
	if piiPolicy == "mask_on_egress" && h.cfg.Filter.Enabled && h.masker != nil {
		MaskRequestContent(req, h.masker, vault)
		res.piiRedacted = vault.RedactedCount()
	}

	if !h.checkCloudQuota(w, clientName) {
		res.handled = true
		return res
	}

	if req.Stream() {
		cloudResp, err := h.callCloudStream(r.Context(), req, res.model)
		if err != nil {
			h.quotaMgr.RefundCloud(clientName)
			log.Printf("[Proxy %s] Cloud streaming error: %v", reqID, err)
			writeOpenAIError(w, http.StatusBadGateway, "gateway_error", "upstream_error", fmt.Sprintf("inference tier failed: %v", err))
			h.recordAudit(reqID, clientName, res.target, res.model, startTime, 0, res.piiRedacted, http.StatusBadGateway)
			res.handled = true
			return res
		}
		res.resp = cloudResp
		return res
	}

	rawBody, err := h.callCloudNonStreaming(r.Context(), req, res.model)
	if err != nil {
		h.quotaMgr.RefundCloud(clientName)
		log.Printf("[Proxy %s] Cloud non-streaming error: %v", reqID, err)
		writeOpenAIError(w, http.StatusBadGateway, "gateway_error", "upstream_error", fmt.Sprintf("inference tier failed: %v", err))
		h.recordAudit(reqID, clientName, res.target, res.model, startTime, 0, res.piiRedacted, http.StatusBadGateway)
		res.handled = true
		return res
	}
	res.rawBody = rawBody
	return res
}

func (h *Handler) handleStreaming(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	req *Request,
	decision *router.Decision,
	vault *filter.Vault,
	startTime time.Time,
	clientName string,
	piiPolicy string,
	localOnly bool,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeOpenAIError(w, http.StatusInternalServerError, "server_error", "streaming_unsupported", "streaming unsupported by client")
		return
	}

	// SSE responses routinely outlive the server-wide WriteTimeout: a slow local
	// model can legitimately stream for minutes. Disabling the deadline outright
	// would let a dead peer pin a goroutine forever, so instead we install a
	// rolling idle deadline that is refreshed on every successful flush.
	touchDeadline := newStreamDeadlineRefresher(w, h.cfg.Server.StreamIdleTimeoutMs)

	res := h.dispatch(w, r, reqID, req, decision, vault, startTime, clientName, piiPolicy, localOnly, false)
	if res.handled {
		return
	}
	if res.cancel != nil {
		defer res.cancel()
	}
	defer res.resp.Body.Close()

	finalTarget := res.target
	finalModel := res.model
	ttftMs := res.ttftMs
	piiRedacted := res.piiRedacted
	firstChunk := res.firstChunk
	usingLocal := res.usingLocal
	upstreamResp := res.resp

	// Write SSE Response Headers
	touchDeadline()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-EdgeCat-Route", finalTarget)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	streamRehydrator := NewStreamRehydratorWithOptions(vault, h.cfg.Filter.BlockAPIKeyToolRehydrate)
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(firstChunk), upstreamResp.Body))

	idleTimeout := h.router.LocalStreamIdleTimeout()
	if finalTarget == router.TargetCloud {
		idleTimeout = time.Duration(h.cfg.Server.StreamIdleTimeoutMs) * time.Millisecond
	}

	var upstreamIdleTimedOut atomic.Bool
	idleTimer := time.AfterFunc(idleTimeout, func() {
		upstreamIdleTimedOut.Store(true)
		_ = upstreamResp.Body.Close()
	})
	defer idleTimer.Stop()

	writeEvent := func(lines []string) {
		if len(lines) == 0 {
			return
		}
		touchDeadline()
		for _, l := range lines {
			_, _ = w.Write([]byte(l))
			_, _ = w.Write([]byte("\n"))
		}
		_, _ = w.Write([]byte("\n"))
		flusher.Flush()
	}

	var eventLines []string
	streamStatus := http.StatusOK
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if len(lineBytes) > 0 {
			idleTimer.Reset(idleTimeout)
			if ttftMs == 0 {
				ttftMs = time.Since(startTime).Milliseconds()
			}
			line := strings.TrimRight(string(lineBytes), "\r\n")

			if line == "" {
				// Empty line signals end of SSE event
				if len(eventLines) > 0 {
					writeEvent(eventLines)
					eventLines = nil
				}
			} else if strings.HasPrefix(line, "data:") {
				payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if payload == "[DONE]" {
					// Stream completion: flush any buffered pending prefixes before [DONE]
					tailEvents := streamRehydrator.FlushPendingChunks()
					for _, tailEvent := range tailEvents {
						writeEvent([]string{tailEvent})
					}
					eventLines = append(eventLines, "data: [DONE]")
					writeEvent(eventLines)
					eventLines = nil
				} else if strings.HasPrefix(payload, "{") {
					processedLine := streamRehydrator.ProcessJSONLine(line, payload)
					eventLines = append(eventLines, processedLine)
				} else {
					eventLines = append(eventLines, line)
				}
			} else {
				// Comments or other event headers (event:, id:, : ...)
				eventLines = append(eventLines, line)
			}
		}

		if readErr != nil {
			if upstreamIdleTimedOut.Load() {
				log.Printf("[Proxy %s] Upstream stream idle timeout (%v)", reqID, idleTimeout)
				streamStatus = http.StatusGatewayTimeout
				if len(eventLines) > 0 {
					writeEvent(eventLines)
					eventLines = nil
				}
				writeEvent([]string{sseErrorEvent("upstream_idle_timeout", "upstream stream idle timeout")})
			} else if !errors.Is(readErr, io.EOF) {
				if r.Context().Err() != nil {
					streamStatus = StatusClientClosedRequest
				} else {
					log.Printf("[Proxy %s] Upstream stream read error: %v", reqID, readErr)
					streamStatus = http.StatusBadGateway
					if len(eventLines) > 0 {
						writeEvent(eventLines)
						eventLines = nil
					}
					writeEvent([]string{sseErrorEvent("upstream_stream_error", readErr.Error())})
				}
			}
			break
		}
	}

	if usingLocal {
		switch streamStatus {
		case http.StatusOK:
			h.router.RecordLocalOutcome(router.OutcomeSuccess)
		case StatusClientClosedRequest:
			h.router.RecordLocalOutcome(router.OutcomeNeutral)
		default:
			h.router.RecordLocalOutcome(router.OutcomeFailure)
		}
	}

	// Flush any leftover lines
	if len(eventLines) > 0 {
		writeEvent(eventLines)
		eventLines = nil
	}

	// Flush any remaining tail in rehydrators if stream closed without [DONE]
	if streamStatus == http.StatusOK {
		tailEvents := streamRehydrator.FlushPendingChunks()
		for _, tailEvent := range tailEvents {
			writeEvent([]string{tailEvent})
		}
	}

	// Log audit record asynchronously
	h.recordAudit(reqID, clientName, finalTarget, finalModel, startTime, ttftMs, piiRedacted, streamStatus)
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

func newUpstreamRequest(ctx context.Context, endpoint, apiKey string, req *Request, targetModel string) (*http.Request, error) {
	req.SetModel(targetModel)
	payload, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(endpoint, "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return httpReq, nil
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
	ttftTimeout := h.router.LocalTTFTTimeout()
	ttftTimer := time.NewTimer(ttftTimeout)
	defer ttftTimer.Stop()

	localCtx, localCancel := context.WithCancel(ctx)
	httpReq, err := newUpstreamRequest(localCtx, h.router.LocalEndpoint(), h.router.LocalAPIKey(), req, targetModel)
	if err != nil {
		localCancel()
		return nil, nil, 0, nil, err
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
		return nil, nil, 0, nil, &upstreamStatusError{tier: "local", code: resp.StatusCode}
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
	cloudCtx, cancel := context.WithCancel(ctx)
	headerTimer := time.AfterFunc(h.router.CloudTimeout(), func() {
		cancel()
	})
	defer headerTimer.Stop()

	httpReq, err := newUpstreamRequest(cloudCtx, h.router.CloudEndpoint(), h.router.CloudAPIKey(), req, targetModel)
	if err != nil {
		cancel()
		return nil, err
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("cloud connection failed: %w", err)
	}
	headerTimer.Stop()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, &upstreamStatusError{tier: "cloud", code: resp.StatusCode, body: string(body)}
	}

	return resp, nil
}

func (h *Handler) handleNonStreaming(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	req *Request,
	decision *router.Decision,
	vault *filter.Vault,
	startTime time.Time,
	strictJSON bool,
	clientName string,
	piiPolicy string,
	localOnly bool,
) {
	// Even though the client requested a non-streaming response, calling local with
	// stream:true lets us reuse the strict TTFT cutoff, while allowing healthy long
	// generations to proceed without timing out arbitrarily.
	res := h.dispatch(w, r, reqID, req, decision, vault, startTime, clientName, piiPolicy, localOnly, true)
	if res.handled {
		return
	}

	finalTarget := res.target
	finalModel := res.model
	ttftMs := res.ttftMs
	piiRedacted := res.piiRedacted
	rawResp := res.rawBody

	if res.usingLocal {
		localResp := res.resp
		firstChunk := res.firstChunk
		cancelLocal := res.cancel

		isSSE := strings.Contains(strings.ToLower(localResp.Header.Get("Content-Type")), "text/event-stream") ||
			bytes.HasPrefix(bytes.TrimSpace(firstChunk), []byte("data:")) ||
			bytes.HasPrefix(bytes.TrimSpace(firstChunk), []byte(":"))

		if isSSE {
			reader := bufio.NewReader(io.MultiReader(bytes.NewReader(firstChunk), localResp.Body))
			aggData, aggErr := ReadAndAggregateStream(reader, h.router.LocalStreamIdleTimeout(), cancelLocal, finalModel)
			localResp.Body.Close()
			cancelLocal()
			h.router.ReleaseLocal()
			decision.AcquiredLocal = false

			if aggErr != nil {
				if r.Context().Err() != nil {
					h.router.RecordLocalOutcome(router.OutcomeNeutral)
					h.recordAudit(reqID, clientName, finalTarget, finalModel, startTime, ttftMs, piiRedacted, StatusClientClosedRequest)
					return
				}
				h.router.RecordLocalOutcome(router.OutcomeFailure)
				log.Printf("[Proxy %s] Local stream aggregation failed: %v", reqID, aggErr)

				statusCode := http.StatusBadGateway
				errCode := "local_stream_error"
				errMsg := fmt.Sprintf("local stream aggregation failed: %v", aggErr)
				var streamErr *UpstreamStreamError
				switch {
				case errors.Is(aggErr, ErrUpstreamIdleTimeout):
					statusCode = http.StatusGatewayTimeout
					errCode = "upstream_idle_timeout"
					errMsg = "local stream idle timeout"
				case errors.Is(aggErr, ErrUpstreamTruncated):
					statusCode = http.StatusBadGateway
					errCode = "upstream_truncated"
					errMsg = "local stream ended unexpectedly before completion"
				case errors.As(aggErr, &streamErr):
					statusCode = http.StatusBadGateway
					errCode = "upstream_stream_error"
					errMsg = streamErr.Message
				}

				writeOpenAIError(w, statusCode, "gateway_error", errCode, errMsg)
				h.recordAudit(reqID, clientName, finalTarget, finalModel, startTime, ttftMs, piiRedacted, statusCode)
				return
			}

			h.router.RecordLocalOutcome(router.OutcomeSuccess)
			rawResp = aggData
		} else {
			// Local tier returned non-streaming JSON directly
			remainder, readErr := io.ReadAll(localResp.Body)
			localResp.Body.Close()
			cancelLocal()
			h.router.ReleaseLocal()
			decision.AcquiredLocal = false

			if readErr != nil {
				h.router.RecordLocalOutcome(router.OutcomeFailure)
				log.Printf("[Proxy %s] Local read failed: %v", reqID, readErr)
				writeOpenAIError(w, http.StatusBadGateway, "gateway_error", "upstream_error", fmt.Sprintf("local inference failed: %v", readErr))
				h.recordAudit(reqID, clientName, finalTarget, finalModel, startTime, ttftMs, piiRedacted, http.StatusBadGateway)
				return
			}

			h.router.RecordLocalOutcome(router.OutcomeSuccess)
			rawResp = append(firstChunk, remainder...)
		}
	}

	// 3. Contract Strict JSON Enforcement & Single Repair Loop
	if strictJSON {
		rawResp = h.enforceStrictJSON(r.Context(), reqID, clientName, finalTarget, finalModel, rawResp)
	}

	// 4. Rehydrate Vault Placeholders on the raw payload.
	// Re-encoding through typed structs here would silently strip tool_calls,
	// reasoning_content and every vendor extension the upstream returned.
	outBytes := RehydrateBodySafe(vault, rawResp, h.cfg.Filter.BlockAPIKeyToolRehydrate)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-EdgeCat-Route", finalTarget)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outBytes)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(outBytes)

	// Async SQLite audit
	h.recordAudit(reqID, clientName, finalTarget, finalModel, startTime, ttftMs, piiRedacted, http.StatusOK)
}

// enforceStrictJSON strips code fences from choices[0].message.content and
// triggers at most one bounded repair call. It only rewrites that single field
// and returns the payload untouched on any structural surprise, so unknown
// response fields survive the round trip.
func (h *Handler) enforceStrictJSON(
	ctx context.Context,
	reqID, clientName, target, model string,
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
		return h.invokeRepair(callCtx, clientName, target, model, broken)
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
	callCtx, cancel := context.WithTimeout(ctx, h.router.LocalStreamIdleTimeout())
	defer cancel()

	httpReq, err := newUpstreamRequest(callCtx, h.router.LocalEndpoint(), h.router.LocalAPIKey(), req, targetModel)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, &upstreamStatusError{tier: "local", code: resp.StatusCode}
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
	callCtx, cancel := context.WithTimeout(ctx, h.router.CloudTimeout())
	defer cancel()

	httpReq, err := newUpstreamRequest(callCtx, h.router.CloudEndpoint(), h.router.CloudAPIKey(), req, targetModel)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, &upstreamStatusError{tier: "cloud", code: resp.StatusCode, body: string(body)}
	}

	return io.ReadAll(resp.Body)
}

// invokeRepair executes a single repair prompt using the active inference tier.
func (h *Handler) invokeRepair(
	ctx context.Context,
	clientName, target, model, broken string,
) (string, error) {
	repairReq := newRepairRequest(model, broken)

	var data []byte
	var err error
	if target == router.TargetLocal {
		data, err = h.callLocalNonStreaming(ctx, repairReq, model)
	} else {
		if h.quotaMgr != nil {
			if status := h.quotaMgr.CheckAndIncrementCloud(clientName); status != quota.StatusAllowed {
				return "", fmt.Errorf("cloud repair blocked by quota policy (%d)", status)
			}
		}
		data, err = h.callCloudNonStreaming(ctx, repairReq, model)
		if err != nil && h.quotaMgr != nil {
			h.quotaMgr.RefundCloud(clientName)
		}
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
