// Package proxy implements OpenAI-compatible HTTP and SSE governance handlers for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// StatusClientClosedRequest is the non-standard (nginx) status recorded in the
// audit log when the downstream client disconnects before the response ends.
// It is never written to the wire.
const StatusClientClosedRequest = 499

// Errors surfaced by upstream stream readers.
var (
	// ErrUpstreamIdleTimeout: upstream stayed silent longer than the idle timeout.
	ErrUpstreamIdleTimeout = errors.New("upstream idle timeout")
	// ErrUpstreamTruncated: upstream closed the stream without [DONE] or any finish_reason.
	ErrUpstreamTruncated = errors.New("upstream stream truncated before completion")
)

// UpstreamStreamError carries an in-band `data: {"error": ...}` event emitted by upstream mid-stream.
type UpstreamStreamError struct {
	Message string
}

func (e *UpstreamStreamError) Error() string {
	return "upstream stream error: " + e.Message
}

// upstreamStatusError is returned when an upstream tier answers with HTTP >= 400.
type upstreamStatusError struct {
	tier string
	code int
	body string
}

func (e *upstreamStatusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("%s tier returned status %d", e.tier, e.code)
	}
	return fmt.Sprintf("%s tier returned status %d: %s", e.tier, e.code, e.body)
}

// writeOpenAIError writes an OpenAI-shaped JSON error. The message is always
// JSON-encoded, so upstream bodies containing quotes cannot corrupt the payload.
func writeOpenAIError(w http.ResponseWriter, status int, errType, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openAIErrorBody(errType, code, message))
}

func openAIErrorBody(errType, code, message string) map[string]any {
	return map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    errType,
			"code":    code,
		},
	}
}

// sseErrorEvent renders an in-band SSE error event for streams whose headers are already sent.
func sseErrorEvent(code, message string) string {
	b, err := marshalObject(openAIErrorBody("gateway_error", code, message))
	if err != nil {
		return `data: {"error":{"message":"gateway error","type":"gateway_error","code":"gateway_error"}}`
	}
	return "data: " + string(b)
}

// clientNameOf returns the audit/quota identity of an authenticated client.
func clientNameOf(name string) string {
	if name == "" {
		return "anonymous"
	}
	return name
}
