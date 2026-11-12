// Package proxy implements OpenAI-compatible HTTP and SSE governance handlers for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy

import (
	"encoding/json"
	"strings"

	"github.com/patchcat-dev/edgecat/internal/filter"
)

// StreamRehydrator manages per-choice and per-field sliding-window rehydrators
// across streaming SSE events to guarantee that PII placeholders split across
// adjacent SSE JSON frames are completely restored.
type StreamRehydrator struct {
	vault                *filter.Vault
	contentRehydrators   map[int]*filter.SlidingRehydrator
	reasoningRehydrators map[int]*filter.SlidingRehydrator
	toolCallRehydrators  map[int]map[int]*filter.SlidingRehydrator
	lastID               string
	lastModel            string
}

// NewStreamRehydrator initializes a stream rehydrator attached to the request vault.
func NewStreamRehydrator(vault *filter.Vault) *StreamRehydrator {
	return &StreamRehydrator{
		vault:                vault,
		contentRehydrators:   make(map[int]*filter.SlidingRehydrator),
		reasoningRehydrators: make(map[int]*filter.SlidingRehydrator),
		toolCallRehydrators:  make(map[int]map[int]*filter.SlidingRehydrator),
	}
}

func (s *StreamRehydrator) getContentRehydrator(choiceIdx int) *filter.SlidingRehydrator {
	r, ok := s.contentRehydrators[choiceIdx]
	if !ok {
		r = filter.NewSlidingRehydrator(s.vault)
		s.contentRehydrators[choiceIdx] = r
	}
	return r
}

func (s *StreamRehydrator) getReasoningRehydrator(choiceIdx int) *filter.SlidingRehydrator {
	r, ok := s.reasoningRehydrators[choiceIdx]
	if !ok {
		r = filter.NewSlidingRehydrator(s.vault)
		s.reasoningRehydrators[choiceIdx] = r
	}
	return r
}

func (s *StreamRehydrator) getToolCallRehydrator(choiceIdx, toolIdx int) *filter.SlidingRehydrator {
	choiceMap, ok := s.toolCallRehydrators[choiceIdx]
	if !ok {
		choiceMap = make(map[int]*filter.SlidingRehydrator)
		s.toolCallRehydrators[choiceIdx] = choiceMap
	}
	r, ok := choiceMap[toolIdx]
	if !ok {
		r = filter.NewSlidingRehydrator(s.vault)
		choiceMap[toolIdx] = r
	}
	return r
}

// ProcessJSONLine parses an SSE data payload, rehydrates any placeholders inside
// delta fields (content, reasoning_content, tool arguments), and re-encodes it.
// If decoding fails, it returns the raw line unmodified.
func (s *StreamRehydrator) ProcessJSONLine(rawLine, payload string) string {
	if s.vault == nil || s.vault.RedactedCount() == 0 {
		return rawLine
	}

	dec := json.NewDecoder(strings.NewReader(payload))
	dec.UseNumber()

	var chunkObj map[string]any
	if err := dec.Decode(&chunkObj); err != nil || chunkObj == nil {
		return rawLine
	}

	if id, ok := chunkObj["id"].(string); ok && id != "" {
		s.lastID = id
	}
	if m, ok := chunkObj["model"].(string); ok && m != "" {
		s.lastModel = m
	}

	s.rehydrateChunkObject(chunkObj)

	reEncoded, err := marshalObject(chunkObj)
	if err != nil {
		return rawLine
	}

	return "data: " + string(reEncoded)
}

func (s *StreamRehydrator) rehydrateChunkObject(chunkObj map[string]any) {
	choices, ok := chunkObj["choices"].([]any)
	if !ok {
		return
	}

	for _, rawChoice := range choices {
		choice, ok := rawChoice.(map[string]any)
		if !ok {
			continue
		}
		choiceIdx := parseChoiceIndex(choice["index"])

		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			continue
		}

		// 1. content
		if contentStr, ok := delta["content"].(string); ok {
			r := s.getContentRehydrator(choiceIdx)
			delta["content"] = r.Feed(contentStr)
		}

		// 2. reasoning_content
		if reasoningStr, ok := delta["reasoning_content"].(string); ok {
			r := s.getReasoningRehydrator(choiceIdx)
			delta["reasoning_content"] = r.Feed(reasoningStr)
		}

		// 3. tool_calls
		if toolCalls, ok := delta["tool_calls"].([]any); ok {
			for _, rawTool := range toolCalls {
				toolCall, ok := rawTool.(map[string]any)
				if !ok {
					continue
				}
				toolIdx := parseChoiceIndex(toolCall["index"])
				if fn, ok := toolCall["function"].(map[string]any); ok {
					if argsStr, ok := fn["arguments"].(string); ok {
						r := s.getToolCallRehydrator(choiceIdx, toolIdx)
						fn["arguments"] = r.Feed(argsStr)
					}
				}
			}
		}
	}
}

// FlushPendingChunks returns any residual unclosed buffer contents as synthetic
// SSE delta events before the stream is closed or before [DONE].
func (s *StreamRehydrator) FlushPendingChunks() []string {
	if s.vault == nil || s.vault.RedactedCount() == 0 {
		return nil
	}

	var chunks []string
	id := s.lastID
	if id == "" {
		id = "chatcmpl-flush"
	}
	model := s.lastModel
	if model == "" {
		model = "default"
	}

	// 1. Flush content buffers
	for choiceIdx, r := range s.contentRehydrators {
		if tail := r.Flush(); tail != "" {
			eventObj := map[string]any{
				"id":     id,
				"object": "chat.completion.chunk",
				"model":  model,
				"choices": []any{
					map[string]any{
						"index": choiceIdx,
						"delta": map[string]any{
							"content": tail,
						},
						"finish_reason": nil,
					},
				},
			}
			if b, err := marshalObject(eventObj); err == nil {
				chunks = append(chunks, "data: "+string(b))
			}
		}
	}

	// 2. Flush reasoning_content buffers
	for choiceIdx, r := range s.reasoningRehydrators {
		if tail := r.Flush(); tail != "" {
			eventObj := map[string]any{
				"id":     id,
				"object": "chat.completion.chunk",
				"model":  model,
				"choices": []any{
					map[string]any{
						"index": choiceIdx,
						"delta": map[string]any{
							"reasoning_content": tail,
						},
						"finish_reason": nil,
					},
				},
			}
			if b, err := marshalObject(eventObj); err == nil {
				chunks = append(chunks, "data: "+string(b))
			}
		}
	}

	// 3. Flush tool_calls arguments buffers
	for choiceIdx, choiceMap := range s.toolCallRehydrators {
		for toolIdx, r := range choiceMap {
			if tail := r.Flush(); tail != "" {
				eventObj := map[string]any{
					"id":     id,
					"object": "chat.completion.chunk",
					"model":  model,
					"choices": []any{
						map[string]any{
							"index": choiceIdx,
							"delta": map[string]any{
								"tool_calls": []any{
									map[string]any{
										"index": toolIdx,
										"function": map[string]any{
											"arguments": tail,
										},
									},
								},
							},
							"finish_reason": nil,
						},
					},
				}
				if b, err := marshalObject(eventObj); err == nil {
					chunks = append(chunks, "data: "+string(b))
				}
			}
		}
	}

	return chunks
}

func parseChoiceIndex(v any) int {
	switch val := v.(type) {
	case json.Number:
		if i, err := val.Int64(); err == nil {
			return int(i)
		}
	case float64:
		return int(val)
	case int:
		return val
	}
	return 0
}
