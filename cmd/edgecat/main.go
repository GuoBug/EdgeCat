// EdgeCat - Local-First AI Inference Governance Gateway
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/patchcat-dev/edgecat/internal/audit"
	"github.com/patchcat-dev/edgecat/internal/config"
	"github.com/patchcat-dev/edgecat/internal/contract"
	"github.com/patchcat-dev/edgecat/internal/filter"
	"github.com/patchcat-dev/edgecat/internal/proxy"
	"github.com/patchcat-dev/edgecat/internal/router"
)

const banner = `
  ______    _             _____       _   
 |  ____|  | |           / ____|     | |  
 | |__   __| | __ _  ___| |      __ _| |_ 
 |  __| / _' |/ _' |/ _ \ |     / _' | __|
 | |___| (_| | (_| |  __/ |____| (_| | |_ 
 |______\__,_|\__, |\___|\_____|\__,_|\__|
               __/ |                      
              |___/                       
  Local-First AI Inference Governance Gateway
  Copyright (c) 2026 Guo Qiang (Apache-2.0)
`

func main() {
	configPath := flag.String("config", "configs/edgecat.example.yaml", "Path to YAML/JSON configuration file")
	flag.Parse()

	fmt.Print(banner)

	// 1. Load configuration
	log.Printf("[Init] Loading configuration from %s ...", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[Init] Failed to load configuration: %v", err)
	}

	// 2. Initialize asynchronous SQLite audit logger
	log.Printf("[Init] Initializing SQLite audit logger at %s (batch: %d, flush: %dms, queue: %d) ...",
		cfg.Audit.SQLitePath, cfg.Audit.BatchSize, cfg.Audit.FlushIntervalMs, cfg.Audit.QueueSize)
	auditLogger, err := audit.NewLogger(
		cfg.Audit.SQLitePath,
		cfg.Audit.BatchSize,
		cfg.Audit.FlushIntervalMs,
		cfg.Audit.QueueSize,
	)
	if err != nil {
		log.Fatalf("[Init] Failed to initialize audit logger: %v", err)
	}
	defer func() {
		log.Println("[Shutdown] Flushing and closing audit logger ...")
		_ = auditLogger.Close()
	}()

	// 3. Initialize PII filter and Masker
	masker := filter.NewMasker(
		cfg.Filter.MaskPhone,
		cfg.Filter.MaskEmail,
		cfg.Filter.MaskIPv4,
		cfg.Filter.MaskAPIKey,
	)
	log.Printf("[Init] PII filter enabled: %v (Phone: %v, Email: %v, IPv4: %v, APIKey: %v)",
		cfg.Filter.Enabled, cfg.Filter.MaskPhone, cfg.Filter.MaskEmail, cfg.Filter.MaskIPv4, cfg.Filter.MaskAPIKey)

	// 4. Initialize Router with concurrency semaphore and TTFT fallback
	r := router.NewRouter(cfg)
	log.Printf("[Init] Router initialized. Local max concurrency: %d, Local TTFT timeout: %dms",
		cfg.Local.MaxConcurrentLocal, cfg.Local.TTFTTimeoutMs)

	// 5. Initialize Contract Guard
	guard := contract.NewGuard(
		cfg.Contract.StrictJSONEnabled,
		cfg.Contract.MaxRepairAttempts,
		cfg.Contract.RepairTimeoutMs,
	)

	// 6. Initialize Proxy Handler
	handler := proxy.NewHandler(cfg, masker, r, guard, auditLogger)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeoutMs) * time.Millisecond,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeoutMs) * time.Millisecond,
	}

	// 7. Start HTTP Server
	go func() {
		log.Printf("[Server] EdgeCat listening on http://%s", addr)
		log.Printf("[Server] Ingress endpoints: /v1/chat/completions, /health, /v1/models")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Server] HTTP server encountered fatal error: %v", err)
		}
	}()

	// 8. Graceful shutdown on SIGINT / SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	sig := <-quit
	log.Printf("[Server] Received shutdown signal: %v. Initiating graceful drain...", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Server] Server shutdown error: %v", err)
	}

	log.Println("[Server] Gateway exited cleanly.")
}
