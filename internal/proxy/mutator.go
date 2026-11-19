// Package proxy implements OpenAI-compatible HTTP and SSE governance handlers for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy

import (
	"context"
	"net/http"
)

// MutationStage identifies which phase of the inbound governance pipeline is executing.
type MutationStage int

const (
	// StagePreMask runs after JSON parsing and client authentication, before PII
	// policy evaluation and masking. Any text injected in this stage (such as
	// system prompts or retrieved memory facts) is automatically protected by
	// EdgeCat's PII filter before leaving the local network.
	StagePreMask MutationStage = iota + 1

	// StagePostMask runs after PII policy evaluation and eager masking,
	// immediately before routing admission (DecideRouteWithContext). Mutators in
	// this stage can inspect redaction counts or tighten routing constraints
	// (such as enforcing LocalOnly or tuning QueueWaitMs).
	StagePostMask
)

// String returns a human-readable stage name for logging and diagnostics.
func (s MutationStage) String() string {
	switch s {
	case StagePreMask:
		return "pre_mask"
	case StagePostMask:
		return "post_mask"
	default:
		return "unknown"
	}
}

// RequestMeta carries per-request governance context across both mutation stages.
type RequestMeta struct {
	// Immutable request identity and headers.
	RequestID  string
	ClientName string
	HTTPHeader http.Header

	// Stage indicates the currently executing mutation phase.
	Stage MutationStage

	// Mutable governance knobs evaluated before routing:
	// - PIIPolicy may be adjusted in StagePreMask ("mask_always", "mask_on_egress", "local_only", "block").
	// - LocalOnly may be set to true in either stage to forbid cloud fallback.
	//   Once PII policy enforces LocalOnly=true, StagePostMask cannot downgrade it back to false.
	// - QueueWaitMs may be tuned in either stage before local concurrency admission.
	PIIPolicy   string
	LocalOnly   bool
	QueueWaitMs int

	// PIIRedactedCount is populated before StagePostMask (0 under mask_on_egress
	// until cloud fallback actually executes).
	PIIRedactedCount int

	// Values is an isolated per-request scratchpad allowing mutators to pass
	// state from StagePreMask to StagePostMask without modifying wire JSON.
	Values map[string]any
}

// RequestMutator defines EdgeCat's two-stage inbound request extension hook (R3.1).
//
// Registered mutators run sequentially in registration order at StagePreMask
// (before PII masking) and again at StagePostMask (after PII masking, before
// routing). Returning a non-nil error aborts the request before upstream
// dispatch; return a *MutatorError to customize the HTTP status and OpenAI
// error payload.
type RequestMutator interface {
	Name() string
	MutatePreMask(ctx context.Context, req *Request, meta *RequestMeta) error
	MutatePostMask(ctx context.Context, req *Request, meta *RequestMeta) error
}

// MutatorError allows a RequestMutator to reject a request with a specific
// HTTP status code and OpenAI-compatible error envelope.
type MutatorError struct {
	StatusCode int
	Type       string
	Code       string
	Message    string
}

// Error implements the error interface.
func (e *MutatorError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Code != "" {
		return e.Code
	}
	return "request rejected by mutator"
}

// MutatorFunc is a function signature for a single-stage mutation callback.
type MutatorFunc func(ctx context.Context, req *Request, meta *RequestMeta) error

// MutatorFuncs adapts optional PreMask and/or PostMask callbacks into a RequestMutator.
// Nil callbacks act as no-ops.
type MutatorFuncs struct {
	MutatorName string
	PreMask     MutatorFunc
	PostMask    MutatorFunc
}

// Name returns the mutator's diagnostic name.
func (m MutatorFuncs) Name() string {
	if m.MutatorName != "" {
		return m.MutatorName
	}
	return "unnamed_mutator"
}

// MutatePreMask invokes PreMask if non-nil.
func (m MutatorFuncs) MutatePreMask(ctx context.Context, req *Request, meta *RequestMeta) error {
	if m.PreMask == nil {
		return nil
	}
	return m.PreMask(ctx, req, meta)
}

// MutatePostMask invokes PostMask if non-nil.
func (m MutatorFuncs) MutatePostMask(ctx context.Context, req *Request, meta *RequestMeta) error {
	if m.PostMask == nil {
		return nil
	}
	return m.PostMask(ctx, req, meta)
}

// PreMaskMutatorFunc wraps a StagePreMask-only callback as a RequestMutator.
func PreMaskMutatorFunc(name string, fn MutatorFunc) RequestMutator {
	return MutatorFuncs{
		MutatorName: name,
		PreMask:     fn,
	}
}

// PostMaskMutatorFunc wraps a StagePostMask-only callback as a RequestMutator.
func PostMaskMutatorFunc(name string, fn MutatorFunc) RequestMutator {
	return MutatorFuncs{
		MutatorName: name,
		PostMask:    fn,
	}
}

// HandlerOption configures optional extensions on a proxy Handler.
type HandlerOption func(*Handler)

// WithRequestMutators registers one or more two-stage RequestMutator hooks on a Handler.
func WithRequestMutators(mutators ...RequestMutator) HandlerOption {
	return func(h *Handler) {
		h.UseMutator(mutators...)
	}
}
