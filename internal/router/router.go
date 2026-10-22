// Package router manages tier routing, local concurrency semaphores,
// TTFT-driven circuit breaking, and model alias rewriting for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package router

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/patchcat-dev/edgecat/internal/config"
)

const (
	TargetLocal = "local"
	TargetCloud = "cloud"
)

// Decision captures the selected tier, target model, and acquired resources.
type Decision struct {
	Target        string // "local" or "cloud"
	TargetModel   string
	AcquiredLocal bool
	Reason        string
}

// Router orchestrates local and cloud tier dispatching.
type Router struct {
	cfg           *config.Config
	localSem      chan struct{}
	localDisabled bool
	localFallback atomic.Int64 // counter of fallbacks triggered
}

// NewRouter initializes the router and concurrency semaphore.
func NewRouter(cfg *config.Config) *Router {
	maxLocal := cfg.Local.MaxConcurrentLocal
	if maxLocal <= 0 {
		maxLocal = 1
	}

	disabled := strings.TrimSpace(cfg.Local.Endpoint) == ""

	return &Router{
		cfg:           cfg,
		localSem:      make(chan struct{}, maxLocal),
		localDisabled: disabled,
	}
}

// ResolveModel maps an incoming logical model to the target tier's physical model.
func (r *Router) ResolveModel(target, logicalModel string) string {
	var mapping map[string]string
	if target == TargetLocal {
		mapping = r.cfg.Local.ModelMapping
	} else {
		mapping = r.cfg.Cloud.ModelMapping
	}

	if mapping != nil {
		if mapped, exists := mapping[logicalModel]; exists && mapped != "" {
			return mapped
		}
		if defaultModel, exists := mapping["default"]; exists && defaultModel != "" {
			return defaultModel
		}
	}

	return logicalModel
}

// TryAcquireLocal attempts to acquire a concurrency slot for the local inference tier.
func (r *Router) TryAcquireLocal() bool {
	if r.localDisabled {
		return false
	}
	select {
	case r.localSem <- struct{}{}:
		return true
	default:
		return false
	}
}

// ReleaseLocal releases a previously acquired local concurrency slot.
func (r *Router) ReleaseLocal() {
	select {
	case <-r.localSem:
	default:
	}
}

// CurrentLocalConcurrency returns the number of active requests on the local tier.
func (r *Router) CurrentLocalConcurrency() int {
	return len(r.localSem)
}

// MaxLocalConcurrency returns the maximum concurrent slots configured for local tier.
func (r *Router) MaxLocalConcurrency() int {
	return cap(r.localSem)
}

// DecideRoute selects between Local Tier and Cloud Tier based on semaphore availability.
func (r *Router) DecideRoute(logicalModel string) Decision {
	if r.localDisabled {
		return Decision{
			Target:        TargetCloud,
			TargetModel:   r.ResolveModel(TargetCloud, logicalModel),
			AcquiredLocal: false,
			Reason:        "local_tier_not_configured",
		}
	}

	if r.TryAcquireLocal() {
		return Decision{
			Target:        TargetLocal,
			TargetModel:   r.ResolveModel(TargetLocal, logicalModel),
			AcquiredLocal: true,
			Reason:        "local_semaphore_acquired",
		}
	}

	// Concurrency saturated -> Fallback to Cloud immediately
	r.localFallback.Add(1)
	return Decision{
		Target:        TargetCloud,
		TargetModel:   r.ResolveModel(TargetCloud, logicalModel),
		AcquiredLocal: false,
		Reason:        "local_concurrency_saturated",
	}
}

// LocalEndpoint returns the URL of the local tier endpoint.
func (r *Router) LocalEndpoint() string {
	return r.cfg.Local.Endpoint
}

// LocalAPIKey returns the API key for the local tier endpoint.
func (r *Router) LocalAPIKey() string {
	return r.cfg.Local.APIKey
}

// LocalTTFTTimeout returns the Time-To-First-Token timeout for the local tier.
func (r *Router) LocalTTFTTimeout() time.Duration {
	ms := r.cfg.Local.TTFTTimeoutMs
	if ms <= 0 {
		ms = 3500
	}
	return time.Duration(ms) * time.Millisecond
}

// CloudEndpoint returns the URL of the cloud tier endpoint.
func (r *Router) CloudEndpoint() string {
	return r.cfg.Cloud.Endpoint
}

// CloudAPIKey returns the API key for the cloud tier endpoint.
func (r *Router) CloudAPIKey() string {
	return r.cfg.Cloud.APIKey
}

// CloudTimeout returns the total timeout for cloud tier calls.
func (r *Router) CloudTimeout() time.Duration {
	ms := r.cfg.Cloud.TimeoutMs
	if ms <= 0 {
		ms = 60000
	}
	return time.Duration(ms) * time.Millisecond
}

// RecordFallback logs a fallback event to cloud tier.
func (r *Router) RecordFallback() {
	r.localFallback.Add(1)
}

// TotalFallbacks returns the cumulative count of fallbacks triggered.
func (r *Router) TotalFallbacks() int64 {
	return r.localFallback.Load()
}
