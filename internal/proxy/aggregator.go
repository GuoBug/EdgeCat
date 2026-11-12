// Package proxy implements OpenAI-compatible HTTP and SSE governance handlers for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package proxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// ErrUpstreamIdleTimeout is returned when an upstream stream is silent longer than the idle timeout.
var ErrUpstreamIdleTimeout = errors.New("upstream idle timeout")

// StreamAggregator parses SSE chunks from a model stream and aggregates them into
// a complete non-streaming chat completion JSON response object.
type StreamAggregator struct {
	id          string
	created     any
	model       string
	usage       any
	choices     map[int]*choiceAccumulator
	finishSeen  bool
}

type choiceAccumulator struct {
	index            int
	role             string
	content          strings.Builder
	hasContent       bool
	reasoningContent strings.Builder
	hasReasoning     bool
	toolCalls        map[int]*toolCallAccumulator
	finishReason     any
}

type toolCallAccumulator struct {
	index     int
	id        string
	callType  string
	name      string
	arguments strings.Builder
}

// NewStreamAggregator initializes an SSE stream-to-JSON aggregator.
func NewStreamAggregator() *StreamAggregator {
	return &StreamAggregator{
		choices: make(map[int]*choiceAccumulator),
	}
}

// FeedChunk parses a chunk JSON object and merges its delta fields into the aggregate.
func (a *StreamAggregator) FeedChunk(chunkObj map[string]any) {
	if id, ok := chunkObj["id"].(string); ok && id != "" && a.id == "" {
		a.id = id
	}
	if created, exists := chunkObj["created"]; exists && a.created == nil {
		a.created = created
	}
	if model, ok := chunkObj["model"].(string); ok && model != "" && a.model == "" {
		a.model = model
	}
	if usage, exists := chunkObj["usage"]; exists && usage != nil {
		a.usage = usage
	}

	choices, ok := chunkObj["choices"].([]any)
	if !ok {
		return
	}

	for _, rawChoice := range choices {
		choice, ok := rawChoice.(map[string]any)
		if !ok {
			continue
		}
		cIdx := parseChoiceIndex(choice["index"])
		acc, exists := a.choices[cIdx]
		if !exists {
			acc = &choiceAccumulator{
				index:     cIdx,
				toolCalls: make(map[int]*toolCallAccumulator),
			}
			a.choices[cIdx] = acc
		}

		if fr, exists := choice["finish_reason"]; exists && fr != nil {
			acc.finishReason = fr
			a.finishSeen = true
		}

		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			continue
		}

		if role, ok := delta["role"].(string); ok && role != "" {
			acc.role = role
		}

		if content, ok := delta["content"].(string); ok {
			acc.content.WriteString(content)
			acc.hasContent = true
		}

		if reasoning, ok := delta["reasoning_content"].(string); ok {
			acc.reasoningContent.WriteString(reasoning)
			acc.hasReasoning = true
		}

		if toolCalls, ok := delta["tool_calls"].([]any); ok {
			for _, rawTool := range toolCalls {
				toolCall, ok := rawTool.(map[string]any)
				if !ok {
					continue
				}
				tIdx := parseChoiceIndex(toolCall["index"])
				tc, exists := acc.toolCalls[tIdx]
				if !exists {
					tc = &toolCallAccumulator{
						index:    tIdx,
						callType: "function",
					}
					acc.toolCalls[tIdx] = tc
				}

				if id, ok := toolCall["id"].(string); ok && id != "" {
					tc.id = id
				}
				if tType, ok := toolCall["type"].(string); ok && tType != "" {
					tc.callType = tType
				}
				if fn, ok := toolCall["function"].(map[string]any); ok {
					if name, ok := fn["name"].(string); ok && name != "" {
						tc.name = name
					}
					if args, ok := fn["arguments"].(string); ok {
						tc.arguments.WriteString(args)
					}
				}
			}
		}
	}
}

// Build marshals the accumulated state into standard OpenAI chat completion JSON bytes.
func (a *StreamAggregator) Build(fallbackModel string) ([]byte, error) {
	finalModel := a.model
	if finalModel == "" {
		finalModel = fallbackModel
	}
	finalID := a.id
	if finalID == "" {
		finalID = generateRequestID()
	}
	finalCreated := a.created
	if finalCreated == nil {
		finalCreated = time.Now().Unix()
	}

	choiceIndices := make([]int, 0, len(a.choices))
	for idx := range a.choices {
		choiceIndices = append(choiceIndices, idx)
	}
	sort.Ints(choiceIndices)

	choicesList := make([]any, 0, len(choiceIndices))
	for _, cIdx := range choiceIndices {
		acc := a.choices[cIdx]
		role := acc.role
		if role == "" {
			role = "assistant"
		}

		msg := map[string]any{
			"role": role,
		}

		if acc.hasContent {
			msg["content"] = acc.content.String()
		} else if len(acc.toolCalls) > 0 {
			msg["content"] = nil
		} else {
			msg["content"] = ""
		}

		if acc.hasReasoning {
			msg["reasoning_content"] = acc.reasoningContent.String()
		}

		if len(acc.toolCalls) > 0 {
			toolIndices := make([]int, 0, len(acc.toolCalls))
			for tIdx := range acc.toolCalls {
				toolIndices = append(toolIndices, tIdx)
			}
			sort.Ints(toolIndices)

			tcList := make([]any, 0, len(toolIndices))
			for _, tIdx := range toolIndices {
				tc := acc.toolCalls[tIdx]
				callType := tc.callType
				if callType == "" {
					callType = "function"
				}
				callID := tc.id
				if callID == "" {
					callID = fmt.Sprintf("call_%d", tIdx)
				}
				tcMap := map[string]any{
					"id":   callID,
					"type": callType,
					"function": map[string]any{
						"name":      tc.name,
						"arguments": tc.arguments.String(),
					},
				}
				tcList = append(tcList, tcMap)
			}
			msg["tool_calls"] = tcList
		}

		finishReason := acc.finishReason
		if finishReason == nil {
			if len(acc.toolCalls) > 0 {
				finishReason = "tool_calls"
			} else {
				finishReason = "stop"
			}
		}

		choiceObj := map[string]any{
			"index":         acc.index,
			"message":       msg,
			"finish_reason": finishReason,
		}
		choicesList = append(choicesList, choiceObj)
	}

	// If no choices were accumulated, create default empty choice
	if len(choicesList) == 0 {
		choicesList = append(choicesList, map[string]any{
			"index": 0,
			"message": map[string]any{
				"role":    "assistant",
				"content": "",
			},
			"finish_reason": "stop",
		})
	}

	finalObj := map[string]any{
		"id":      finalID,
		"object":  "chat.completion",
		"created": finalCreated,
		"model":   finalModel,
		"choices": choicesList,
	}
	if a.usage != nil {
		finalObj["usage"] = a.usage
	}

	return marshalObject(finalObj)
}

// ReadAndAggregateStream reads an SSE stream line by line with an idle timeout.
// It resets the idle timer on every line read from upstream. If upstream stays silent
// longer than idleTimeout, it cancels cancelFunc and returns ErrUpstreamIdleTimeout.
func ReadAndAggregateStream(
	reader *bufio.Reader,
	idleTimeout time.Duration,
	cancelFunc func(),
	fallbackModel string,
) ([]byte, error) {
	aggregator := NewStreamAggregator()

	var timedOut atomic.Bool
	timer := time.AfterFunc(idleTimeout, func() {
		timedOut.Store(true)
		if cancelFunc != nil {
			cancelFunc()
		}
	})
	defer timer.Stop()

	for {
		lineBytes, err := reader.ReadBytes('\n')
		if len(lineBytes) > 0 {
			timer.Reset(idleTimeout)
			line := strings.TrimRight(string(lineBytes), "\r\n")
			if strings.HasPrefix(line, "data:") {
				payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if payload == "[DONE]" {
					break
				}
				if strings.HasPrefix(payload, "{") {
					var chunkObj map[string]any
					dec := json.NewDecoder(strings.NewReader(payload))
					dec.UseNumber()
					if decErr := dec.Decode(&chunkObj); decErr == nil && chunkObj != nil {
						aggregator.FeedChunk(chunkObj)
					}
				}
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if timedOut.Load() {
				return nil, ErrUpstreamIdleTimeout
			}
			return nil, err
		}
	}

	if timedOut.Load() {
		return nil, ErrUpstreamIdleTimeout
	}

	return aggregator.Build(fallbackModel)
}
