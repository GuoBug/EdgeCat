// Package main provides a lightweight mock LLM upstream for testing EdgeCat.
//
// Copyright (c) 2026 Guo Qiang. Distributed under the terms of the Apache License 2.0.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type ChatRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Stream bool `json:"stream"`
}

func main() {
	port := "11434"
	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req ChatRequest
		_ = json.Unmarshal(body, &req)

		lastMsg := ""
		if len(req.Messages) > 0 {
			lastMsg = req.Messages[len(req.Messages)-1].Content
		}

		log.Printf("[Mock Upstream] Received Model=%s | Stream=%v", req.Model, req.Stream)
		log.Printf("[Mock Upstream] Received Upstream Content (Should be MASKED): %s", lastMsg)

		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			flusher, _ := w.(http.Flusher)

			// Send chunk 1: partial reply
			chunk1 := fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":\"[Mock Echo] I heard: %s\"}}]}\n\n", lastMsg)
			_, _ = w.Write([]byte(chunk1))
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(50 * time.Millisecond)

			// Send chunk 2: completion & [DONE]
			chunk2 := "data: {\"choices\":[{\"delta\":{\"content\":\" (Governance verified!)\"}}]}\n\n"
			_, _ = w.Write([]byte(chunk2))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
			return
		}

		// Non-streaming response
		replyContent := fmt.Sprintf("[Mock Echo] Your request contained: %s. Output format is valid JSON.", lastMsg)
		resp := map[string]any{
			"id":      "mock-chatcmpl-001",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   req.Model,
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]string{
						"role":    "assistant",
						"content": replyContent,
					},
					"finish_reason": "stop",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	log.Printf("[Mock Upstream] Listening on http://127.0.0.1:%s (Simulating Ollama / vLLM)...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
