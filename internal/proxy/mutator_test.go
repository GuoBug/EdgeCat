// Package proxy_test tests the two-stage RequestMutator extension hook (R3.1).
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/patchcat-dev/edgecat/internal/audit"
	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/contract"
	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/proxy"
	"github.com/patchcat-dev/edgecat/internal/quota"
	"github.com/patchcat-dev/edgecat/internal/router"
)

func TestRequestMutator_TwoStageOrderingAndPreMaskPIIProtection(t *testing.T) {
	const injectedPhone = "13800138000"
	var upstreamPayload []byte

	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		upstreamPayload, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"echo {{EC_PII_PHONE_1}}"}}]}`))
	}))
	defer cloud.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = "" // Route directly to cloud
	cfg.Cloud.Endpoint = cloud.URL
	cfg.Filter.Enabled = true
	cfg.Filter.Policy = "mask_always"
	cfg.Filter.MaskPhone = true

	var trace []string
	var postMaskRedactedCount int
	var postMaskSharedValue any

	m1 := proxy.MutatorFuncs{
		MutatorName: "memory-injector",
		PreMask: func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
			trace = append(trace, "m1:"+meta.Stage.String())
			meta.Values["injected_by"] = "m1"
			// Inject sensitive PII in PreMask; EdgeCat MUST mask it before upstream dispatch.
			req.PrependSystemMessage("Fact: user phone is " + injectedPhone)
			return nil
		},
		PostMask: func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
			trace = append(trace, "m1:"+meta.Stage.String())
			postMaskRedactedCount = meta.PIIRedactedCount
			postMaskSharedValue = meta.Values["injected_by"]
			return nil
		},
	}

	m2 := proxy.MutatorFuncs{
		MutatorName: "param-tuner",
		PreMask: func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
			trace = append(trace, "m2:"+meta.Stage.String())
			req.Set("temperature", 0.2)
			return nil
		},
		PostMask: func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
			trace = append(trace, "m2:"+meta.Stage.String())
			return nil
		},
	}

	h := newTestHandler(t, cfg)
	h.UseMutator(nil, m1, m2)

	rec := postChatCompletion(t, h, `{"model":"default","messages":[{"role":"user","content":"hello"}],"stream":false}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	expectedTrace := []string{"m1:pre_mask", "m2:pre_mask", "m1:post_mask", "m2:post_mask"}
	if !reflect.DeepEqual(trace, expectedTrace) {
		t.Fatalf("unexpected execution order: got %v, want %v", trace, expectedTrace)
	}

	if postMaskRedactedCount != 1 {
		t.Fatalf("expected PostMask to observe PIIRedactedCount=1, got %d", postMaskRedactedCount)
	}
	if postMaskSharedValue != "m1" {
		t.Fatalf("expected meta.Values to persist across stages, got %v", postMaskSharedValue)
	}

	// Security invariant: raw phone injected in PreMask must NEVER reach cloud upstream.
	if strings.Contains(string(upstreamPayload), injectedPhone) {
		t.Fatalf("PII leaked to upstream: %s", string(upstreamPayload))
	}
	if !strings.Contains(string(upstreamPayload), "{{EC_PII_PHONE_1}}") {
		t.Fatalf("expected masked placeholder in upstream payload, got: %s", string(upstreamPayload))
	}
	if !strings.Contains(string(upstreamPayload), `"temperature":0.2`) {
		t.Fatalf("expected mutated temperature in upstream payload, got: %s", string(upstreamPayload))
	}

	// Client response must be rehydrated back to the original phone number.
	if !strings.Contains(rec.Body.String(), injectedPhone) {
		t.Fatalf("expected rehydrated phone in response, got: %s", rec.Body.String())
	}
}

func TestRequestMutator_PostMaskCannotDowngradePIILocalOnly(t *testing.T) {
	var cloudCalls atomic.Int32
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cloudCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = "" // Local unavailable
	cfg.Cloud.Endpoint = cloud.URL
	cfg.Filter.Enabled = true
	cfg.Filter.Policy = "local_only"
	cfg.Filter.MaskPhone = true

	h := newTestHandler(t, cfg)
	// Malicious or buggy PostMask mutator attempts to unset LocalOnly.
	h.UseMutator(proxy.PostMaskMutatorFunc("downgrade-attempt", func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
		if !meta.LocalOnly {
			t.Errorf("expected meta.LocalOnly=true after PII local_only evaluation")
		}
		meta.LocalOnly = false
		return nil
	}))

	rec := postChatCompletion(t, h, `{"model":"default","messages":[{"role":"user","content":"call 13800138000"}],"stream":false}`, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when PII local_only is enforced, got %d: %s", rec.Code, rec.Body.String())
	}
	if cloudCalls.Load() != 0 {
		t.Fatalf("expected 0 cloud calls, got %d", cloudCalls.Load())
	}
}

func TestRequestMutator_SetLogicalModelAffectsCloudFallback(t *testing.T) {
	var receivedModel string
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedModel, _ = body["model"].(string)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-2","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer cloud.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = "" // Go straight to cloud
	cfg.Cloud.Endpoint = cloud.URL
	cfg.Cloud.ModelMapping = map[string]string{
		"default": "gpt-4o-mini",
		"coding":  "cloud-coding-pro",
	}

	h := newTestHandler(t, cfg)
	h.UseMutator(proxy.PreMaskMutatorFunc("model-router", func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
		req.SetLogicalModel("coding")
		return nil
	}))

	rec := postChatCompletion(t, h, `{"model":"default","messages":[{"role":"user","content":"write go"}],"stream":false}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if receivedModel != "cloud-coding-pro" {
		t.Fatalf("expected cloud model 'cloud-coding-pro', got %q", receivedModel)
	}
}

func TestRequestMutator_RejectionWithCustomAndDefaultErrors(t *testing.T) {
	var cloudCalls atomic.Int32
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cloudCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()

	cfg := config.DefaultConfig()
	cfg.Local.Endpoint = ""
	cfg.Cloud.Endpoint = cloud.URL
	cfg.Filter.Enabled = true
	cfg.Filter.Policy = "mask_always"
	cfg.Filter.MaskPhone = true

	// Case 1: PreMask custom *MutatorError
	t.Run("PreMask_CustomMutatorError", func(t *testing.T) {
		h := newTestHandler(t, cfg)
		h.UseMutator(proxy.PreMaskMutatorFunc("policy-blocker", func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
			return &proxy.MutatorError{
				StatusCode: http.StatusForbidden,
				Type:       "policy_error",
				Code:       "topic_forbidden",
				Message:    "this topic is blocked by local policy",
			}
		}))

		rec := postChatCompletion(t, h, `{"model":"default","messages":[{"role":"user","content":"hi"}],"stream":false}`, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
		}
		var errResp map[string]map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("decode error envelope: %v", err)
		}
		if errResp["error"]["code"] != "topic_forbidden" || errResp["error"]["type"] != "policy_error" {
			t.Fatalf("unexpected error envelope: %+v", errResp)
		}
	})

	// Case 2: PostMask plain error (defaults to 400 mutator_rejected)
	t.Run("PostMask_PlainError", func(t *testing.T) {
		h := newTestHandler(t, cfg)
		h.UseMutator(proxy.PostMaskMutatorFunc("pii-threshold", func(ctx context.Context, req *proxy.Request, meta *proxy.RequestMeta) error {
			if meta.PIIRedactedCount > 0 {
				return errors.New("redacted PII count exceeds budget")
			}
			return nil
		}))

		rec := postChatCompletion(t, h, `{"model":"default","messages":[{"role":"user","content":"phone 13800138000"}],"stream":false}`, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
		var errResp map[string]map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("decode error envelope: %v", err)
		}
		if errResp["error"]["code"] != "mutator_rejected" {
			t.Fatalf("expected code mutator_rejected, got %+v", errResp)
		}
	})

	if cloudCalls.Load() != 0 {
		t.Fatalf("upstream should never be called on mutator rejection, got %d calls", cloudCalls.Load())
	}
}

func TestRequestMutator_WithOptionAndAdminStatusObservability(t *testing.T) {
	cfg := config.DefaultConfig()
	logger, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.db"), 10, 100, 100)
	if err != nil {
		t.Fatalf("init audit logger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	qm, err := quota.NewManager(logger.DB(), cfg.Auth.Clients)
	if err != nil {
		t.Fatalf("init quota manager: %v", err)
	}
	masker := filter.NewMasker(true, true, true, true)
	guard := contract.NewGuard(false, 1, 5000)

	h := proxy.NewHandler(
		cfg, masker, router.NewRouter(cfg), guard, logger, qm,
		proxy.WithRequestMutators(
			proxy.PreMaskMutatorFunc("first-hook", nil),
			nil,
			proxy.PostMaskMutatorFunc("second-hook", nil),
		),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body struct {
		Mutators []string `json:"mutators"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode admin status: %v", err)
	}
	want := []string{"first-hook", "second-hook"}
	if !reflect.DeepEqual(body.Mutators, want) {
		t.Fatalf("expected mutators %v in /admin/status, got %v", want, body.Mutators)
	}
}
