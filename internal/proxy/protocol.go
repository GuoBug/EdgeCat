// Package proxy implements OpenAI-compatible HTTP and SSE governance handlers for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/patchcat-dev/edgecat/internal/filter"
)

// Request is a lossless view over an OpenAI-compatible chat completion request.
//
// EdgeCat must never reconstruct a client payload from a typed struct. Any field
// the gateway does not model (tools, tool_choice, top_p, presence_penalty,
// multimodal content parts, vendor extensions) would be silently dropped on the
// re-encode, which silently breaks every tool-calling client. Instead the
// decoded object is kept verbatim and only the fields EdgeCat actually mutates
// are rewritten.
type Request struct {
	logicalModel string
	fields       map[string]any
}

// ParseRequest decodes a request body into a lossless mutable object.
// Numbers are decoded as json.Number so that re-encoding keeps the original
// numeric literal instead of round-tripping through float64.
func ParseRequest(body []byte) (*Request, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var fields map[string]any
	if err := dec.Decode(&fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, fmt.Errorf("request body must be a JSON object")
	}
	logicalModel, _ := fields["model"].(string)
	return &Request{
		logicalModel: logicalModel,
		fields:       fields,
	}, nil
}

// Model returns the immutable logical model originally requested by the client.
// Even after SetModel rewrites the outbound wire field for the local tier,
// Model still returns the original client model so cloud fallback resolution
// maps from the client's logical model rather than the local physical model.
func (r *Request) Model() string {
	return r.logicalModel
}

// SetModel rewrites the model field in place (used by tier model aliasing).
func (r *Request) SetModel(model string) {
	r.fields["model"] = model
}

// Stream reports whether the client asked for an SSE response.
func (r *Request) Stream() bool {
	s, _ := r.fields["stream"].(bool)
	return s
}

// ResponseFormatType returns response_format.type, or "" when absent.
func (r *Request) ResponseFormatType() string {
	rf, ok := r.fields["response_format"].(map[string]any)
	if !ok {
		return ""
	}
	t, _ := rf["type"].(string)
	return t
}

// Messages returns the raw message array. It may be nil for malformed payloads.
func (r *Request) Messages() []any {
	msgs, _ := r.fields["messages"].([]any)
	return msgs
}

// Marshal re-encodes the request. HTML escaping is disabled so that payloads are
// forwarded byte-similar to what the client sent.
func (r *Request) Marshal() ([]byte, error) {
	return marshalObject(r.fields)
}

// MaskRequestContent applies PII masking to every textual field of the request.
//
// Multimodal content arrays are masked part-by-part: image/audio payloads are
// forwarded untouched while their text parts are still redacted. Tool call
// arguments are masked as well, because an agent forwarding a user's phone
// number to a tool is just as much of a leak as putting it in the prompt.
func MaskRequestContent(req *Request, masker *filter.Masker, vault *filter.Vault) {
	if req == nil || masker == nil || vault == nil {
		return
	}

	for _, raw := range req.Messages() {
		msg, ok := raw.(map[string]any)
		if !ok {
			continue
		}

		if content, exists := msg["content"]; exists {
			msg["content"] = maskContentValue(content, masker, vault)
		}

		toolCalls, ok := msg["tool_calls"].([]any)
		if !ok {
			continue
		}
		for _, rawCall := range toolCalls {
			call, ok := rawCall.(map[string]any)
			if !ok {
				continue
			}
			fn, ok := call["function"].(map[string]any)
			if !ok {
				continue
			}
			if args, ok := fn["arguments"].(string); ok {
				fn["arguments"] = masker.MaskText(args, vault)
			}
		}
	}
}

// maskContentValue handles both the plain-string content shape and the
// multimodal array shape ([{"type":"text","text":"..."},{"type":"image_url",...}]).
func maskContentValue(content any, masker *filter.Masker, vault *filter.Vault) any {
	switch value := content.(type) {
	case string:
		return masker.MaskText(value, vault)
	case []any:
		for _, rawPart := range value {
			part, ok := rawPart.(map[string]any)
			if !ok {
				continue
			}
			if part["type"] != "text" {
				continue
			}
			if text, ok := part["text"].(string); ok {
				part["text"] = masker.MaskText(text, vault)
			}
		}
		return value
	default:
		return content
	}
}

// RehydrateBody restores PII placeholders inside a raw JSON payload without
// re-encoding it.
//
// Substituting on the raw bytes is safe because placeholders only contain
// [A-Za-z0-9_], and every masked value type (phone, email, private IPv4, API
// key) is likewise restricted to characters that need no JSON escaping.
// Avoiding a decode/encode round trip here is what keeps tool_calls,
// reasoning_content and vendor extensions intact on the way back to the client.
func RehydrateBody(vault *filter.Vault, raw []byte) []byte {
	if vault == nil || len(raw) == 0 {
		return raw
	}
	return []byte(vault.Rehydrate(string(raw)))
}

// decodeObject decodes a JSON object preserving numeric literals.
func decodeObject(raw []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

// firstChoiceContent extracts choices[0].message.content.
// It reports false when the response is not a chat completion, or when the
// first choice carries only tool_calls and no textual content.
func firstChoiceContent(obj map[string]any) (string, bool) {
	choices, ok := obj["choices"].([]any)
	if !ok || len(choices) == 0 {
		return "", false
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		return "", false
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		return "", false
	}
	content, ok := message["content"].(string)
	return content, ok
}

// setFirstChoiceContent writes choices[0].message.content back in place.
func setFirstChoiceContent(obj map[string]any, content string) bool {
	choices, ok := obj["choices"].([]any)
	if !ok || len(choices) == 0 {
		return false
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		return false
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		return false
	}
	message["content"] = content
	return true
}

// newRepairRequest builds the internal single-shot JSON repair prompt.
func newRepairRequest(model, broken string) *Request {
	return &Request{
		logicalModel: model,
		fields: map[string]any{
			"model":  model,
			"stream": false,
			"messages": []any{
				map[string]any{
					"role":    "system",
					"content": "You are a strict JSON repair engine. Output ONLY syntactically valid JSON. Do not include markdown code blocks, explanation, or commentary.",
				},
				map[string]any{
					"role":    "user",
					"content": fmt.Sprintf("The following output was malformed JSON:\n%s\nRepair it and return ONLY valid JSON:", broken),
				},
			},
		},
	}
}

// marshalObject encodes a JSON object without HTML escaping and without the
// trailing newline that json.Encoder appends, so Content-Length stays exact.
func marshalObject(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}
