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
	"github.com/patchcat-dev/edgecat/internal/memory"
	"github.com/patchcat-dev/edgecat/internal/proxy"
	"github.com/patchcat-dev/edgecat/internal/quota"
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

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "version", "-version", "--version", "-v":
			fmt.Println(formatVersion())
			return
		case "help", "-h", "--help":
			printUsage(os.Stdout)
			return
		case "init":
			os.Exit(runInit(args[1:], os.Stdout, os.Stderr))
		case "check":
			os.Exit(runCheck(args[1:], os.Stdout, os.Stderr))
		case "ping":
			os.Exit(runPing(args[1:], os.Stdout, os.Stderr))
		case "serve":
			args = args[1:]
		}
	}

	serveFlags := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := serveFlags.String("config", "configs/edgecat.example.yaml", "Path to YAML/JSON configuration file")
	showVersion := serveFlags.Bool("version", false, "Print version and exit")
	_ = serveFlags.Parse(args)
	if *showVersion {
		fmt.Println(formatVersion())
		return
	}

	fmt.Print(banner)
	log.Printf("[Init] %s", formatVersion())

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
	masker := filter.NewMaskerFromRules(
		cfg.Filter.MaskPhone,
		cfg.Filter.MaskEmail,
		cfg.Filter.MaskIPv4,
		cfg.Filter.MaskAPIKey,
		cfg.Filter.MaskIDCard,
		cfg.Filter.MaskBankCard,
	)
	log.Printf("[Init] PII filter enabled: %v (Policy: %s, Phone: %v, Email: %v, IPv4: %v, APIKey: %v, IDCard: %v, BankCard: %v)",
		cfg.Filter.Enabled, cfg.Filter.Policy, cfg.Filter.MaskPhone, cfg.Filter.MaskEmail, cfg.Filter.MaskIPv4, cfg.Filter.MaskAPIKey, cfg.Filter.MaskIDCard, cfg.Filter.MaskBankCard)

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

	// 6. Initialize Quota Manager (for daily cloud limits & multi-device attribution)
	quotaMgr, err := quota.NewManager(auditLogger.DB(), cfg.Auth.Clients)
	if err != nil {
		log.Fatalf("[Init] Failed to initialize quota manager: %v", err)
	}
	defer quotaMgr.Close()

	// 7. Optional: Initialize Opt-In Layered Memory Plugin (R3.2, disabled by default)
	var handlerOpts []proxy.HandlerOption
	var memPlugin *memory.Plugin
	if cfg.Memory.Enabled {
		memPlugin, err = memory.NewPlugin(memory.Options{
			SQLitePath:         cfg.Memory.SQLitePath,
			MaxFacts:           cfg.Memory.MaxFacts,
			MaxShortTerm:       cfg.Memory.MaxShortTerm,
			QueryTimeoutMs:     cfg.Memory.QueryTimeoutMs,
			ReaderMaxOpenConns: cfg.Memory.ReaderMaxOpenConns,
			Masker:             masker,
			HMACSecret:         []byte(cfg.Filter.HMACSecret),
		})
		if err != nil {
			log.Fatalf("[Init] Failed to initialize layered memory plugin: %v", err)
		}
		defer func() { _ = memPlugin.Close() }()
		handlerOpts = append(handlerOpts, proxy.WithRequestMutators(memPlugin))
		log.Printf("[Init] Opt-in layered memory plugin enabled at %s (max_facts=%d, query_timeout=%dms)",
			cfg.Memory.SQLitePath, cfg.Memory.MaxFacts, cfg.Memory.QueryTimeoutMs)
	}

	// 8. Initialize Proxy Handler
	handler := proxy.NewHandler(cfg, masker, r, guard, auditLogger, quotaMgr, handlerOpts...)

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
	errCh := make(chan error, 1)
	go func() {
		log.Printf("[Server] EdgeCat listening on http://%s", addr)
		log.Printf("[Server] Ingress endpoints: /v1/chat/completions, /health, /admin/status, /v1/models")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// 8. Graceful shutdown on SIGINT / SIGTERM or fatal server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		log.Printf("[Server] HTTP server encountered fatal error: %v", err)
		if memPlugin != nil {
			_ = memPlugin.Close()
		}
		quotaMgr.Close()
		_ = auditLogger.Close()
		os.Exit(1)
	case sig := <-quit:
		log.Printf("[Server] Received shutdown signal: %v. Initiating graceful drain...", sig)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Server] Server shutdown error: %v", err)
	}

	log.Println("[Server] Gateway exited cleanly.")
}
