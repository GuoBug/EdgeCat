// Package router manages tier routing, local concurrency semaphores,
// TTFT-driven circuit breaking, and model alias rewriting for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package router

import (
	"sync"
	"time"
)

// Breaker states.
const (
	BreakerClosed   = "closed"
	BreakerOpen     = "open"
	BreakerHalfOpen = "half_open"
)

// Outcome classifies how a local-tier attempt ended, for breaker accounting.
type Outcome int

const (
	// OutcomeSuccess: local answered (first token, or a 4xx proving it is alive).
	OutcomeSuccess Outcome = iota
	// OutcomeFailure: connection refused/unreachable, TTFT timeout, 5xx, or a mid-stream stall.
	OutcomeFailure
	// OutcomeNeutral: the attempt ended for reasons unrelated to local health
	// (e.g. the downstream client disconnected). It must still be reported so
	// a half-open probe slot is never leaked.
	OutcomeNeutral
)

// breaker is a classic closed / open / half-open circuit breaker for the local tier.
//
// While open, requests skip the local tier entirely instead of each paying the
// full TTFT timeout against a host that is down or asleep. After the cooldown a
// single probe request is admitted; its outcome decides whether to close again.
type breaker struct {
	mu            sync.Mutex
	state         string
	failures      int
	threshold     int
	cooldown      time.Duration
	openedAt      time.Time
	probeInFlight bool
	now           func() time.Time
}

func newBreaker(threshold int, cooldown time.Duration) *breaker {
	if threshold <= 0 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &breaker{
		state:     BreakerClosed,
		threshold: threshold,
		cooldown:  cooldown,
		now:       time.Now,
	}
}

// allow reports whether a request may attempt the local tier. It returns
// probe=true when the caller holds the single half-open probe slot.
func (b *breaker) allow() (ok bool, probe bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case BreakerClosed:
		return true, false
	case BreakerOpen:
		if b.now().Sub(b.openedAt) >= b.cooldown && !b.probeInFlight {
			b.state = BreakerHalfOpen
			b.probeInFlight = true
			return true, true
		}
		return false, false
	default: // half-open: a probe is already in flight
		return false, false
	}
}

// cancelProbe returns an unused probe slot (e.g. the semaphore was saturated).
func (b *breaker) cancelProbe() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == BreakerHalfOpen {
		b.state = BreakerOpen
		b.probeInFlight = false
		// Keep openedAt in the past so the next request may probe immediately.
	}
}

func (b *breaker) record(o Outcome) {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch o {
	case OutcomeSuccess:
		b.failures = 0
		b.state = BreakerClosed
		b.probeInFlight = false
	case OutcomeFailure:
		if b.state == BreakerHalfOpen {
			b.trip()
			return
		}
		b.failures++
		if b.state == BreakerClosed && b.failures >= b.threshold {
			b.trip()
		}
	case OutcomeNeutral:
		if b.state == BreakerHalfOpen {
			b.state = BreakerOpen
			b.probeInFlight = false
		}
	}
}

func (b *breaker) trip() {
	b.state = BreakerOpen
	b.openedAt = b.now()
	b.probeInFlight = false
}

func (b *breaker) snapshot() (string, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state, b.failures
}
