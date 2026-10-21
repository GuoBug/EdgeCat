// Package contract handles output contract sanitization, JSON validation,
// and bounded repair loops for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package contract

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	// Matches ```json ... ``` or ``` ... ```
	reCodeFence = regexp.MustCompile("(?s)^\\s*```(?:json)?\\s*([\\s\\S]*?)\\s*```\\s*$")
)

// Guard enforces strict JSON output contracts and handles optional one-shot repair.
type Guard struct {
	StrictJSONEnabled bool
	MaxRepairAttempts int
	RepairTimeout     time.Duration
}

// NewGuard creates a JSON contract guard.
func NewGuard(strictJSON bool, maxRepairAttempts int, repairTimeoutMs int) *Guard {
	if maxRepairAttempts < 0 {
		maxRepairAttempts = 0
	} else if maxRepairAttempts > 1 {
		// Strict contract enforces at most 1 repair attempt
		maxRepairAttempts = 1
	}
	if repairTimeoutMs <= 0 {
		repairTimeoutMs = 5000
	}
	return &Guard{
		StrictJSONEnabled: strictJSON,
		MaxRepairAttempts: maxRepairAttempts,
		RepairTimeout:     time.Duration(repairTimeoutMs) * time.Millisecond,
	}
}

// StripCodeFences strips markdown ```json ... ``` code blocks and trims whitespace.
func StripCodeFences(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return trimmed
	}

	// Direct fence match
	if matches := reCodeFence.FindStringSubmatch(trimmed); len(matches) == 2 {
		return strings.TrimSpace(matches[1])
	}

	// Embedded fence fallback (e.g. LLM outputs text before/after the fence)
	idxStart := strings.Index(trimmed, "```")
	if idxStart != -1 {
		fenceContent := trimmed[idxStart+3:]
		// Strip optional language specifier (e.g. "json\n")
		if strings.HasPrefix(strings.ToLower(fenceContent), "json") {
			fenceContent = fenceContent[4:]
		}
		// Strip up to next newline
		if strings.HasPrefix(fenceContent, "\r\n") {
			fenceContent = fenceContent[2:]
		} else if strings.HasPrefix(fenceContent, "\n") {
			fenceContent = fenceContent[1:]
		}

		idxEnd := strings.Index(fenceContent, "```")
		if idxEnd != -1 {
			candidate := strings.TrimSpace(fenceContent[:idxEnd])
			if json.Valid([]byte(candidate)) {
				return candidate
			}
		}
	}

	return trimmed
}

// IsValidJSON checks whether a string is syntactically valid JSON.
func IsValidJSON(s string) bool {
	if s == "" {
		return false
	}
	return json.Valid([]byte(s))
}

// RepairFn is a callback used to invoke the LLM for repairing malformed JSON output.
type RepairFn func(ctx context.Context, brokenJSON string) (string, error)

// EnforceAndRepair strips code fences, validates JSON, and triggers a single repair call if invalid.
func (g *Guard) EnforceAndRepair(ctx context.Context, rawOutput string, repair RepairFn) (string, bool, error) {
	cleaned := StripCodeFences(rawOutput)
	if IsValidJSON(cleaned) {
		return cleaned, false, nil
	}

	// If no repair allowed or no repair callback provided, return failure
	if g.MaxRepairAttempts <= 0 || repair == nil {
		return cleaned, false, fmt.Errorf("contract violation: output is not valid JSON and repair is disabled")
	}

	// Trigger bounded repair loop (at most 1 attempt)
	repairCtx, cancel := context.WithTimeout(ctx, g.RepairTimeout)
	defer cancel()

	repairedRaw, err := repair(repairCtx, rawOutput)
	if err != nil {
		return cleaned, false, fmt.Errorf("contract repair call failed: %w", err)
	}

	repairedClean := StripCodeFences(repairedRaw)
	if IsValidJSON(repairedClean) {
		return repairedClean, true, nil
	}

	return repairedClean, false, fmt.Errorf("contract repair failed: output remains invalid JSON")
}
