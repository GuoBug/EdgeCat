// Package contract_test tests JSON fence stripping, syntax validation,
// and single-shot repair loops.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package contract_test

import (
	"context"
	"testing"

	"github.com/patchcat-dev/edgecat/internal/contract"
)

func TestStripCodeFences(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean json",
			input:    `{"status": "ok"}`,
			expected: `{"status": "ok"}`,
		},
		{
			name:     "fenced json with tag",
			input:    "```json\n{\"foo\": \"bar\"}\n```",
			expected: `{"foo": "bar"}`,
		},
		{
			name:     "fenced json without tag",
			input:    "```\n{\"foo\": \"bar\"}\n```",
			expected: `{"foo": "bar"}`,
		},
		{
			name:     "fenced with outer text",
			input:    "Here is your result:\n```json\n{\"count\": 42}\n```\nHope it helps!",
			expected: `{"count": 42}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := contract.StripCodeFences(tc.input)
			if got != tc.expected {
				t.Fatalf("StripCodeFences(%q) = %q; expected %q", tc.input, got, tc.expected)
			}
			if !contract.IsValidJSON(got) {
				t.Fatalf("expected result %q to be valid JSON", got)
			}
		})
	}
}

func TestEnforceAndRepair_SuccessfulRepair(t *testing.T) {
	guard := contract.NewGuard(true, 1, 3000)

	broken := `{"name": "test", trailing comma,}`
	repairedResponse := `{"name": "test"}`

	repairCalls := 0
	repairFn := func(ctx context.Context, input string) (string, error) {
		repairCalls++
		return repairedResponse, nil
	}

	res, repaired, err := guard.EnforceAndRepair(context.Background(), broken, repairFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !repaired {
		t.Fatalf("expected repaired to be true")
	}
	if repairCalls != 1 {
		t.Fatalf("expected exactly 1 repair call, got %d", repairCalls)
	}
	if res != repairedResponse {
		t.Fatalf("expected %q, got %q", repairedResponse, res)
	}
}
