// Package filter_test tests PII masking, Vault consistency, and sliding-window
// stream rehydration for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package filter_test

import (
	"strings"
	"testing"

	"github.com/patchcat-dev/edgecat/internal/filter"
)

func TestSlidingRehydrator_SplitPlaceholder_ExactRequirement(t *testing.T) {
	// Vault setup with a phone number mapped to {{EC_PII_PHONE_1}}
	vault := filter.NewVault()
	phone := "13812345678"
	placeholder := vault.Mask(filter.TypePhone, phone)
	if placeholder != "{{EC_PII_PHONE_1}}" {
		t.Fatalf("expected placeholder {{EC_PII_PHONE_1}}, got %s", placeholder)
	}

	rehydrator := filter.NewSlidingRehydrator(vault)

	// Step 1: Feed first chunk "{{EC_PII_" (cut in half)
	chunk1 := "{{EC_PII_"
	out1 := rehydrator.Feed(chunk1)
	if out1 != "" {
		t.Fatalf("expected chunk 1 to buffer unclosed prefix and return empty string, got: %q", out1)
	}

	// Step 2: Feed second chunk "PHONE_1}}" (closing the placeholder)
	chunk2 := "PHONE_1}}"
	out2 := rehydrator.Feed(chunk2)

	// Final flush (stream end)
	flushed := rehydrator.Flush()

	fullReconstructed := out1 + out2 + flushed
	if fullReconstructed != phone {
		t.Fatalf("expected reconstructed phone %q, got %q (out1=%q, out2=%q, flushed=%q)",
			phone, fullReconstructed, out1, out2, flushed)
	}
}

func TestSlidingRehydrator_SplitWithSurroundingText(t *testing.T) {
	vault := filter.NewVault()
	phone := "13987654321"
	vault.Mask(filter.TypePhone, phone)

	rehydrator := filter.NewSlidingRehydrator(vault)

	chunk1 := "Contact phone is: {{EC_PII_"
	out1 := rehydrator.Feed(chunk1)
	if out1 != "Contact phone is: " {
		t.Fatalf("expected chunk1 output %q, got %q", "Contact phone is: ", out1)
	}

	chunk2 := "PHONE_1}} for direct assistance."
	out2 := rehydrator.Feed(chunk2)
	expectedOut2 := "13987654321 for direct assistance."
	if out2 != expectedOut2 {
		t.Fatalf("expected chunk2 output %q, got %q", expectedOut2, out2)
	}

	flushed := rehydrator.Flush()
	if flushed != "" {
		t.Fatalf("expected empty flush, got %q", flushed)
	}

	total := out1 + out2 + flushed
	expectedTotal := "Contact phone is: 13987654321 for direct assistance."
	if total != expectedTotal {
		t.Fatalf("expected total %q, got %q", expectedTotal, total)
	}
}

func TestSlidingRehydrator_SplitAcrossThreeChunks(t *testing.T) {
	vault := filter.NewVault()
	apiKey := "sk-live-0123456789abcdef0123456789"
	vault.Mask(filter.TypeAPIKey, apiKey) // will be {{EC_PII_APIKEY_1}}

	rehydrator := filter.NewSlidingRehydrator(vault)

	c1 := "Secret: {{EC_"
	o1 := rehydrator.Feed(c1)
	if o1 != "Secret: " {
		t.Fatalf("expected o1 %q, got %q", "Secret: ", o1)
	}

	c2 := "PII_APIKEY_"
	o2 := rehydrator.Feed(c2)
	if o2 != "" {
		t.Fatalf("expected o2 to be empty, got %q", o2)
	}

	c3 := "1}} (keep safe)"
	o3 := rehydrator.Feed(c3)
	expectedO3 := apiKey + " (keep safe)"
	if o3 != expectedO3 {
		t.Fatalf("expected o3 %q, got %q", expectedO3, o3)
	}

	total := o1 + o2 + o3 + rehydrator.Flush()
	expectedTotal := "Secret: " + apiKey + " (keep safe)"
	if total != expectedTotal {
		t.Fatalf("expected total %q, got %q", expectedTotal, total)
	}
}

func TestMasker_AllPIITypes(t *testing.T) {
	masker := filter.NewMasker(true, true, true, true)
	vault := filter.NewVault()

	input := `User alice at 13800138000 (email: alice@corp.local) accessed server 192.168.1.50 using sk-abcd1234efgh5678ijkl9012`
	masked := masker.MaskText(input, vault)

	if !strings.Contains(masked, "{{EC_PII_PHONE_1}}") {
		t.Errorf("phone placeholder missing: %s", masked)
	}
	if !strings.Contains(masked, "{{EC_PII_EMAIL_1}}") {
		t.Errorf("email placeholder missing: %s", masked)
	}
	if !strings.Contains(masked, "{{EC_PII_IPV4_1}}") {
		t.Errorf("ipv4 placeholder missing: %s", masked)
	}
	if !strings.Contains(masked, "{{EC_PII_APIKEY_1}}") {
		t.Errorf("apikey placeholder missing: %s", masked)
	}

	if vault.RedactedCount() != 4 {
		t.Errorf("expected 4 redacted items, got %d", vault.RedactedCount())
	}

	// Rehydrate and verify 100% round-trip fidelity
	rehydrated := vault.Rehydrate(masked)
	if rehydrated != input {
		t.Errorf("rehydration round-trip mismatch!\nExpected: %s\nGot:      %s", input, rehydrated)
	}
}

func TestVault_DeterministicDeduplication(t *testing.T) {
	vault := filter.NewVault()
	phone := "13800138000"

	p1 := vault.Mask(filter.TypePhone, phone)
	p2 := vault.Mask(filter.TypePhone, phone)

	if p1 != p2 {
		t.Fatalf("expected deterministic placeholder for duplicate value, got %s and %s", p1, p2)
	}
	if vault.RedactedCount() != 1 {
		t.Fatalf("expected redacted count 1, got %d", vault.RedactedCount())
	}
}

func TestSlidingRehydrator_NonPlaceholderBraces(t *testing.T) {
	vault := filter.NewVault()
	rehydrator := filter.NewSlidingRehydrator(vault)

	// Feed JSON with normal curly braces
	c1 := `{"status":`
	o1 := rehydrator.Feed(c1)
	c2 := ` "ok"}`
	o2 := rehydrator.Feed(c2)
	flushed := rehydrator.Flush()

	total := o1 + o2 + flushed
	expected := `{"status": "ok"}`
	if total != expected {
		t.Fatalf("expected %q, got %q", expected, total)
	}
}
