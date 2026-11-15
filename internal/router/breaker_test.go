package router

import (
	"testing"
	"time"

	"github.com/patchcat-dev/edgecat/internal/config"
)

func TestBreaker_ClosedOpenHalfOpenLifecycle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newBreaker(3, 30*time.Second)
	b.now = func() time.Time { return now }

	// 2 failures keep breaker closed
	b.record(OutcomeFailure)
	b.record(OutcomeFailure)
	if st, fails := b.snapshot(); st != BreakerClosed || fails != 2 {
		t.Fatalf("expected closed/2, got %s/%d", st, fails)
	}
	if ok, _ := b.allow(); !ok {
		t.Fatal("expected allow while closed")
	}

	// 3rd failure trips to open
	b.record(OutcomeFailure)
	if st, _ := b.snapshot(); st != BreakerOpen {
		t.Fatalf("expected open after 3 failures, got %s", st)
	}
	if ok, _ := b.allow(); ok {
		t.Fatal("expected fast-fail while open before cooldown")
	}

	// Advance past cooldown: exactly one half-open probe is admitted
	now = now.Add(31 * time.Second)
	ok, probe := b.allow()
	if !ok || !probe {
		t.Fatalf("expected single half-open probe after cooldown, got ok=%v probe=%v", ok, probe)
	}
	if ok2, _ := b.allow(); ok2 {
		t.Fatal("expected second concurrent request to be rejected while probe is in flight")
	}

	// Probe fails -> re-opens
	b.record(OutcomeFailure)
	if st, _ := b.snapshot(); st != BreakerOpen {
		t.Fatalf("expected open after failed probe, got %s", st)
	}

	// Neutral probe outcome (client disconnect) -> returns to open without resetting cooldown
	now = now.Add(31 * time.Second)
	ok, probe = b.allow()
	if !ok || !probe {
		t.Fatal("expected probe after second cooldown")
	}
	b.record(OutcomeNeutral)
	if st, _ := b.snapshot(); st != BreakerOpen {
		t.Fatalf("expected open after neutral probe, got %s", st)
	}

	// Probe succeeds -> closes and resets failure count
	ok, probe = b.allow()
	if !ok || !probe {
		t.Fatal("expected immediate probe after neutral outcome")
	}
	b.record(OutcomeSuccess)
	if st, fails := b.snapshot(); st != BreakerClosed || fails != 0 {
		t.Fatalf("expected closed/0 after successful probe, got %s/%d", st, fails)
	}
}

func TestRouter_BreakerTripsAndRecovers(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Local.BreakerFailureThreshold = 2
	cfg.Local.BreakerCooldownMs = 50
	r := NewRouter(cfg)

	d1 := r.DecideRoute("default")
	if d1.Target != TargetLocal || !d1.AcquiredLocal {
		t.Fatalf("expected local route, got %+v", d1)
	}
	r.ReleaseLocal()
	r.RecordLocalOutcome(OutcomeFailure)

	d2 := r.DecideRoute("default")
	if d2.Target != TargetLocal {
		t.Fatalf("expected local on 2nd attempt, got %+v", d2)
	}
	r.ReleaseLocal()
	r.RecordLocalOutcome(OutcomeFailure)

	// Now breaker must be open -> immediate cloud without acquiring local
	d3 := r.DecideRoute("default")
	if d3.Target != TargetCloud || d3.Reason != "local_circuit_open" {
		t.Fatalf("expected local_circuit_open cloud fallback, got %+v", d3)
	}

	// Wait cooldown -> half-open probe
	time.Sleep(60 * time.Millisecond)
	d4 := r.DecideRoute("default")
	if d4.Target != TargetLocal || !d4.IsProbe {
		t.Fatalf("expected half-open local probe, got %+v", d4)
	}
	r.ReleaseLocal()
	r.RecordLocalOutcome(OutcomeSuccess)

	if st, _ := r.BreakerState(); st != BreakerClosed {
		t.Fatalf("expected breaker closed after probe success, got %s", st)
	}
}
