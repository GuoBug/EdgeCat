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

func TestSlidingRehydrator_SplitBetweenClosingBraces(t *testing.T) {
	vault := filter.NewVault()
	phone := "13812345678"
	vault.Mask(filter.TypePhone, phone) // {{EC_PII_PHONE_1}}

	rehydrator := filter.NewSlidingRehydrator(vault)

	// Chunk 1 ends with single closing brace '}'
	c1 := "{{EC_PII_PHONE_1}"
	o1 := rehydrator.Feed(c1)
	if o1 != "" {
		t.Fatalf("expected o1 to be buffered, got %q", o1)
	}

	// Chunk 2 starts with second closing brace '}'
	c2 := "} now"
	o2 := rehydrator.Feed(c2)
	expectedO2 := phone + " now"
	if o2 != expectedO2 {
		t.Fatalf("expected %q, got %q", expectedO2, o2)
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

func TestMasker_PhoneFormats(t *testing.T) {
	masker := filter.NewMasker(true, false, false, false)

	testCases := []string{
		"13800138000",
		"+8613800138000",
		"+86 13800138000",
		"+86-138-0013-8000",
		"138 0013 8000",
		"138-0013-8000",
		"86 13800138000",
	}

	for _, tc := range testCases {
		vault := filter.NewVault()
		input := "Please call me at " + tc + " right now."
		masked := masker.MaskText(input, vault)

		if strings.Contains(masked, tc) {
			t.Fatalf("failed to mask phone number %q in %q", tc, masked)
		}
		if !strings.Contains(masked, "{{EC_PII_PHONE_1}}") {
			t.Fatalf("expected placeholder {{EC_PII_PHONE_1}} for %q, got %q", tc, masked)
		}
		rehydrated := vault.Rehydrate(masked)
		if rehydrated != input {
			t.Fatalf("rehydrate mismatch for %q: got %q, want %q", tc, rehydrated, input)
		}
	}
}

func TestMasker_IDCard_BankCard_And_APIKeyToolGuard(t *testing.T) {
	masker := filter.NewMaskerFromRules(false, false, false, true, true, true)
	vault := filter.NewVault()

	// Valid 18-digit ID card + valid Luhn 16-digit card (4111111111111111) + non-Luhn 16-digit number + API key
	input := "ID: 11010519900307123X, Card: 4111111111111111, Order: 1234567890123456, Key: sk-live-0123456789abcdef0123456789"
	if !masker.ContainsPII(input) {
		t.Fatal("expected ContainsPII to detect sensitive tokens")
	}
	masked := masker.MaskText(input, vault)
	if !strings.Contains(masked, "{{EC_PII_IDCARD_1}}") {
		t.Fatalf("expected IDCARD placeholder, got %s", masked)
	}
	if !strings.Contains(masked, "{{EC_PII_BANKCARD_1}}") {
		t.Fatalf("expected Luhn-valid BANKCARD placeholder, got %s", masked)
	}
	if !strings.Contains(masked, "1234567890123456") {
		t.Fatalf("expected non-Luhn order number to remain unmasked, got %s", masked)
	}

	// RehydrateExcludingAPIKey must restore IDCARD/BANKCARD but keep APIKEY redacted
	safeToolArgs := vault.RehydrateExcludingAPIKey(masked)
	if !strings.Contains(safeToolArgs, "11010519900307123X") || !strings.Contains(safeToolArgs, "4111111111111111") {
		t.Fatalf("expected IDCARD and BANKCARD restored, got %s", safeToolArgs)
	}
	if strings.Contains(safeToolArgs, "sk-live-") || !strings.Contains(safeToolArgs, "{{EC_PII_APIKEY_1}}") {
		t.Fatalf("expected APIKEY to stay redacted in tool args, got %s", safeToolArgs)
	}
}

func TestStableVault_HMACKeyDeterminismAndStreamingRehydration(t *testing.T) {
	secret := []byte("edgecat-local-homelab-secret-key")
	masker := filter.NewMasker(true, true, true, true)

	v1 := filter.NewStableVault(secret)
	v2 := filter.NewStableVault(secret)
	vOther := filter.NewStableVault([]byte("different-secret"))

	input := "Call 13800138000 now"
	m1 := masker.MaskText(input, v1)
	m2 := masker.MaskText(input, v2)
	mOther := masker.MaskText(input, vOther)

	expectedKey := filter.StableKey("13800138000", secret)
	if len(expectedKey) != 16 {
		t.Fatalf("expected 16 hex chars (8 bytes), got %d (%q)", len(expectedKey), expectedKey)
	}
	expectedPh := "{{EC_PII_PHONE_" + expectedKey + "}}"

	if m1 != "Call "+expectedPh+" now" {
		t.Fatalf("unexpected stable placeholder: got %q, want %q", m1, "Call "+expectedPh+" now")
	}
	if m1 != m2 {
		t.Fatalf("expected identical placeholders across requests, got %q vs %q", m1, m2)
	}
	if m1 == mOther {
		t.Fatalf("different secrets must produce different stable keys: %q", m1)
	}

	// Verify sliding-window SSE rehydration when a 16-hex stable key is split across chunks.
	rehydrator := filter.NewSlidingRehydrator(v1)
	splitAt := len("Call {{EC_PII_PHONE_") + 6
	var out strings.Builder
	out.WriteString(rehydrator.Feed(m1[:splitAt]))
	out.WriteString(rehydrator.Feed(m1[splitAt:]))
	out.WriteString(rehydrator.Flush())

	if out.String() != input {
		t.Fatalf("streaming rehydration failed for stable key: got %q, want %q", out.String(), input)
	}
}
