// Package router_test tests semaphore acquisition, fallback decisions, and model aliasing.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package router_test

import (
	"testing"

	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/router"
)

func TestRouter_ModelAliasing(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Local.ModelMapping = map[string]string{
		"default":     "qwen2.5:7b",
		"gpt-4o-mini": "qwen2.5:7b",
	}
	cfg.Cloud.ModelMapping = map[string]string{
		"default":    "gpt-4o-mini",
		"qwen2.5:7b": "gpt-4o-mini",
	}

	r := router.NewRouter(cfg)

	// Local mapping
	if m := r.ResolveModel(router.TargetLocal, "gpt-4o-mini"); m != "qwen2.5:7b" {
		t.Fatalf("expected qwen2.5:7b, got %s", m)
	}
	if m := r.ResolveModel(router.TargetLocal, "default"); m != "qwen2.5:7b" {
		t.Fatalf("expected qwen2.5:7b, got %s", m)
	}

	// Cloud mapping
	if m := r.ResolveModel(router.TargetCloud, "qwen2.5:7b"); m != "gpt-4o-mini" {
		t.Fatalf("expected gpt-4o-mini, got %s", m)
	}
}

func TestRouter_SemaphoreSaturationFallback(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Local.MaxConcurrentLocal = 2
	r := router.NewRouter(cfg)

	// First two should acquire local
	d1 := r.DecideRoute("gpt-4o-mini")
	if d1.Target != router.TargetLocal || !d1.AcquiredLocal {
		t.Fatalf("expected d1 to be local, got %+v", d1)
	}

	d2 := r.DecideRoute("gpt-4o-mini")
	if d2.Target != router.TargetLocal || !d2.AcquiredLocal {
		t.Fatalf("expected d2 to be local, got %+v", d2)
	}

	// Third should be saturated and fallback to cloud
	d3 := r.DecideRoute("gpt-4o-mini")
	if d3.Target != router.TargetCloud || d3.AcquiredLocal {
		t.Fatalf("expected d3 to fallback to cloud, got %+v", d3)
	}
	if d3.Reason != "local_concurrency_saturated" {
		t.Fatalf("expected reason local_concurrency_saturated, got %s", d3.Reason)
	}

	// Release one and verify local can be acquired again
	r.ReleaseLocal()
	d4 := r.DecideRoute("gpt-4o-mini")
	if d4.Target != router.TargetLocal || !d4.AcquiredLocal {
		t.Fatalf("expected d4 to acquire local after release, got %+v", d4)
	}
}
