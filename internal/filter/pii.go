// Package filter implements PII masking, deterministic vaulting, and
// sliding-window SSE rehydration for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package filter

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

type contextKey string

const vaultContextKey contextKey = "edgecat_pii_vault"

// Standard PII types supported by EdgeCat.
const (
	TypePhone  = "PHONE"
	TypeEmail  = "EMAIL"
	TypeIPv4   = "IPV4"
	TypeAPIKey = "APIKEY"
)

const (
	PlaceholderPrefix = "{{EC_PII_"
	PlaceholderSuffix = "}}"
	MaxPendingLength  = 64
)

var (
	// Placeholder regex for rehydration replacement: {{EC_PII_<TYPE>_<INDEX>}}
	rePlaceholder = regexp.MustCompile(`\{\{EC_PII_[A-Z0-9]+_\d+\}\}`)

	// Chinese mobile numbers (+86 or 11 digits starting with 13-19)
	rePhone = regexp.MustCompile(`(?:\+?86)?\b1[3-9]\d{9}\b`)

	// Standard email pattern
	reEmail = regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)

	// Intranet / Private IPv4 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
	reIPv4 = regexp.MustCompile(`\b(?:10(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){2}|192\.168(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){2}|127(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3})\b`)

	// Common API Keys / Secret tokens (OpenAI, GitHub, Bearer tokens)
	reAPIKey = regexp.MustCompile(`\b(?:sk|sk-proj|ghp|gho|pat|glpat|xoxb|xoxp)-[A-Za-z0-9_\-]{20,}\b`)
)

// Vault stores deterministic mappings between sensitive values and placeholders for a request.
type Vault struct {
	mu            sync.RWMutex
	forward       map[string]string // original -> placeholder
	reverse       map[string]string // placeholder -> original
	typeCounters  map[string]int    // type -> next index
	redactedCount int
}

// NewVault initializes a new request-scoped PII vault.
func NewVault() *Vault {
	return &Vault{
		forward:      make(map[string]string),
		reverse:      make(map[string]string),
		typeCounters: make(map[string]int),
	}
}

// Mask returns an existing placeholder or allocates a new deterministic placeholder for the value.
func (v *Vault) Mask(piiType, original string) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	if placeholder, exists := v.forward[original]; exists {
		return placeholder
	}

	v.typeCounters[piiType]++
	index := v.typeCounters[piiType]
	placeholder := fmt.Sprintf("%s%s_%d%s", PlaceholderPrefix, piiType, index, PlaceholderSuffix)

	v.forward[original] = placeholder
	v.reverse[placeholder] = original
	v.redactedCount++

	return placeholder
}

// Lookup returns the original sensitive value given a placeholder.
func (v *Vault) Lookup(placeholder string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	val, ok := v.reverse[placeholder]
	return val, ok
}

// Rehydrate replaces all known placeholders in text with their original values.
func (v *Vault) Rehydrate(text string) string {
	if text == "" {
		return text
	}
	v.mu.RLock()
	defer v.mu.RUnlock()

	if len(v.reverse) == 0 {
		return text
	}

	return rePlaceholder.ReplaceAllStringFunc(text, func(ph string) string {
		if original, exists := v.reverse[ph]; exists {
			return original
		}
		return ph
	})
}

// RedactedCount returns the number of unique sensitive items redacted in this vault.
func (v *Vault) RedactedCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.redactedCount
}

// GetAllPlaceholders returns a copy of all placeholder to original mappings.
func (v *Vault) GetAllPlaceholders() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	res := make(map[string]string, len(v.reverse))
	for k, val := range v.reverse {
		res[k] = val
	}
	return res
}

// Context helpers for attaching Vault to request Context.
func WithVault(ctx context.Context, vault *Vault) context.Context {
	return context.WithValue(ctx, vaultContextKey, vault)
}

func VaultFromContext(ctx context.Context) *Vault {
	if v, ok := ctx.Value(vaultContextKey).(*Vault); ok {
		return v
	}
	return nil
}

// Masker detects and masks sensitive PII in text content using a Vault.
type Masker struct {
	MaskPhone  bool
	MaskEmail  bool
	MaskIPv4   bool
	MaskAPIKey bool
}

// NewMasker creates a Masker with specified rule flags.
func NewMasker(phone, email, ipv4, apiKey bool) *Masker {
	return &Masker{
		MaskPhone:  phone,
		MaskEmail:  email,
		MaskIPv4:   ipv4,
		MaskAPIKey: apiKey,
	}
}

// MaskText applies enabled PII masking rules to the given text and records to Vault.
func (m *Masker) MaskText(text string, vault *Vault) string {
	if text == "" || vault == nil {
		return text
	}

	result := text

	// 1. API Keys (mask first to prevent substring collisions with other patterns)
	if m.MaskAPIKey {
		result = reAPIKey.ReplaceAllStringFunc(result, func(match string) string {
			return vault.Mask(TypeAPIKey, match)
		})
	}

	// 2. Email addresses
	if m.MaskEmail {
		result = reEmail.ReplaceAllStringFunc(result, func(match string) string {
			return vault.Mask(TypeEmail, match)
		})
	}

	// 3. Intranet IPv4 addresses
	if m.MaskIPv4 {
		result = reIPv4.ReplaceAllStringFunc(result, func(match string) string {
			return vault.Mask(TypeIPv4, match)
		})
	}

	// 4. Phone numbers
	if m.MaskPhone {
		result = rePhone.ReplaceAllStringFunc(result, func(match string) string {
			return vault.Mask(TypePhone, match)
		})
	}

	return result
}

// SlidingRehydrator maintains a lightweight buffer across streaming chunks to prevent
// placeholders (e.g., {{EC_PII_PHONE_1}}) from being cut in half across chunk boundaries.
type SlidingRehydrator struct {
	vault   *Vault
	pending string
}

// NewSlidingRehydrator creates a sliding-window rehydrator attached to the request vault.
func NewSlidingRehydrator(vault *Vault) *SlidingRehydrator {
	return &SlidingRehydrator{
		vault:   vault,
		pending: "",
	}
}

// Feed receives a chunk of streaming text, resolves any completed placeholders,
// holds back any unclosed placeholder prefix at the tail into pending buffer,
// and returns the rehydrated safe text that can be immediately flushed downstream.
func (r *SlidingRehydrator) Feed(chunk string) string {
	combined := r.pending + chunk
	r.pending = ""

	if combined == "" {
		return ""
	}

	// If no vault or no masked items, just check if combined might have unclosed EC prefix
	cut := r.findUnclosedPrefixCut(combined)
	if cut < len(combined) {
		safePart := combined[:cut]
		r.pending = combined[cut:]
		if r.vault != nil {
			return r.vault.Rehydrate(safePart)
		}
		return safePart
	}

	// All content is safe to flush
	if r.vault != nil {
		return r.vault.Rehydrate(combined)
	}
	return combined
}

// Flush returns any remaining bytes in the pending buffer (rehydrated if possible).
func (r *SlidingRehydrator) Flush() string {
	if r.pending == "" {
		return ""
	}
	rem := r.pending
	r.pending = ""
	if r.vault != nil {
		return r.vault.Rehydrate(rem)
	}
	return rem
}

// findUnclosedPrefixCut determines where to cut the text so that any unclosed
// placeholder prefix (like "{{EC_PII_" or "{{EC_") remains in the pending buffer.
// It returns an index in [0, len(s)]. If no unclosed prefix is found, it returns len(s).
func (r *SlidingRehydrator) findUnclosedPrefixCut(s string) int {
	// Look at the portion of s after the last complete "}}"
	lastClose := strings.LastIndex(s, PlaceholderSuffix)
	searchStart := 0
	if lastClose != -1 {
		searchStart = lastClose + len(PlaceholderSuffix)
	}
	tail := s[searchStart:]
	if tail == "" {
		return len(s)
	}

	// Check 1: Does tail contain an explicit unclosed "{{EC_" or "{{EC_PII_"?
	if idx := strings.Index(tail, "{{EC_"); idx != -1 {
		cand := tail[idx:]
		// Verify if candidate looks like an unclosed placeholder:
		// Starts with "{{EC_" and contains only valid characters [A-Za-z0-9_] with no "}}"
		if len(cand) <= MaxPendingLength && isValidPlaceholderCandidate(cand) {
			return searchStart + idx
		}
	}

	// Check 2: Does tail end with a partial prefix of "{{EC_"?
	// Possible partial prefixes: "{{EC", "{{E", "{{", "{"
	prefixes := []string{"{{EC", "{{E", "{{"}
	for _, pfx := range prefixes {
		if strings.HasSuffix(tail, pfx) {
			return len(s) - len(pfx)
		}
	}

	// Also check for trailing single '{' only if it could begin "{{EC_"
	if strings.HasSuffix(tail, "{") {
		return len(s) - 1
	}

	return len(s)
}

// isValidPlaceholderCandidate checks if s starts with "{{EC_" and contains only valid
// placeholder characters [A-Za-z0-9_] without closing "}}".
func isValidPlaceholderCandidate(s string) bool {
	if !strings.HasPrefix(s, "{{EC_") {
		return false
	}
	body := s[len("{{EC_"):]
	for _, ch := range body {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_') {
			return false
		}
	}
	return true
}
