// Package config provides configuration parsing and defaults for EdgeCat.
//
// Copyright (c) 2026 Guo Qiang.
// Distributed under the terms of the Apache License 2.0.

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the complete gateway runtime configuration.
type Config struct {
	Server   ServerConfig   `yaml:"server" json:"server"`
	Local    LocalConfig    `yaml:"local" json:"local"`
	Cloud    CloudConfig    `yaml:"cloud" json:"cloud"`
	Filter   FilterConfig   `yaml:"filter" json:"filter"`
	Contract ContractConfig `yaml:"contract" json:"contract"`
	Audit    AuditConfig    `yaml:"audit" json:"audit"`
}

// ServerConfig configures the inbound HTTP server.
type ServerConfig struct {
	Host           string `yaml:"host" json:"host"`
	Port           int    `yaml:"port" json:"port"`
	ReadTimeoutMs  int    `yaml:"read_timeout_ms" json:"read_timeout_ms"`
	WriteTimeoutMs int    `yaml:"write_timeout_ms" json:"write_timeout_ms"`
	// StreamIdleTimeoutMs replaces WriteTimeoutMs on SSE responses. A stream is
	// bounded by how long it stays silent, not by its total duration, so a slow
	// local model can stream for as long as it keeps producing tokens.
	StreamIdleTimeoutMs int `yaml:"stream_idle_timeout_ms" json:"stream_idle_timeout_ms"`
}

// LocalConfig configures the local inference tier (e.g., Ollama / vLLM / llama.cpp).
type LocalConfig struct {
	Endpoint           string            `yaml:"endpoint" json:"endpoint"`
	APIKey             string            `yaml:"api_key" json:"api_key"`
	MaxConcurrentLocal int               `yaml:"max_concurrent_local" json:"max_concurrent_local"`
	TTFTTimeoutMs      int               `yaml:"ttft_timeout_ms" json:"ttft_timeout_ms"`
	ModelMapping       map[string]string `yaml:"model_mapping" json:"model_mapping"`
}

// CloudConfig configures the cloud fallback tier (e.g., OpenAI / DeepSeek / Qwen API).
type CloudConfig struct {
	Endpoint     string            `yaml:"endpoint" json:"endpoint"`
	APIKey       string            `yaml:"api_key" json:"api_key"`
	TimeoutMs    int               `yaml:"timeout_ms" json:"timeout_ms"`
	ModelMapping map[string]string `yaml:"model_mapping" json:"model_mapping"`
}

// FilterConfig configures the PII detection and masking rules.
type FilterConfig struct {
	Enabled    bool `yaml:"enabled" json:"enabled"`
	MaskPhone  bool `yaml:"mask_phone" json:"mask_phone"`
	MaskEmail  bool `yaml:"mask_email" json:"mask_email"`
	MaskIPv4   bool `yaml:"mask_ipv4" json:"mask_ipv4"`
	MaskAPIKey bool `yaml:"mask_apikey" json:"mask_apikey"`
}

// ContractConfig configures response contract validation and JSON guard.
type ContractConfig struct {
	StrictJSONEnabled bool `yaml:"strict_json_enabled" json:"strict_json_enabled"`
	MaxRepairAttempts int  `yaml:"max_repair_attempts" json:"max_repair_attempts"`
	RepairTimeoutMs   int  `yaml:"repair_timeout_ms" json:"repair_timeout_ms"`
}

// AuditConfig configures asynchronous batch auditing to SQLite.
type AuditConfig struct {
	SQLitePath      string `yaml:"sqlite_path" json:"sqlite_path"`
	BatchSize       int    `yaml:"batch_size" json:"batch_size"`
	FlushIntervalMs int    `yaml:"flush_interval_ms" json:"flush_interval_ms"`
	QueueSize       int    `yaml:"queue_size" json:"queue_size"`
}

// DefaultConfig returns a sane default configuration.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:                "0.0.0.0",
			Port:                8080,
			ReadTimeoutMs:       30000,
			WriteTimeoutMs:      120000,
			StreamIdleTimeoutMs: 300000,
		},
		Local: LocalConfig{
			Endpoint:           "http://127.0.0.1:11434/v1",
			APIKey:             "",
			MaxConcurrentLocal: 2,
			TTFTTimeoutMs:      3500,
			ModelMapping: map[string]string{
				"default":     "qwen2.5:7b",
				"gpt-4o-mini": "qwen2.5:7b",
			},
		},
		Cloud: CloudConfig{
			Endpoint:  "https://api.openai.com/v1",
			APIKey:    "",
			TimeoutMs: 60000,
			ModelMapping: map[string]string{
				"default":    "gpt-4o-mini",
				"qwen2.5:7b": "gpt-4o-mini",
			},
		},
		Filter: FilterConfig{
			Enabled:    true,
			MaskPhone:  true,
			MaskEmail:  true,
			MaskIPv4:   true,
			MaskAPIKey: true,
		},
		Contract: ContractConfig{
			StrictJSONEnabled: true,
			MaxRepairAttempts: 1,
			RepairTimeoutMs:   5000,
		},
		Audit: AuditConfig{
			SQLitePath:      "data/edgecat_audit.db",
			BatchSize:       50,
			FlushIntervalMs: 1000,
			QueueSize:       10000,
		},
	}
}

// LoadConfig reads configuration from file (YAML or JSON).
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse json config: %w", err)
		}
	default:
		// Default to YAML
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse yaml config: %w", err)
		}
	}

	applySanityChecks(cfg)
	return cfg, nil
}

func applySanityChecks(cfg *Config) {
	if cfg.Server.Port <= 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Local.MaxConcurrentLocal <= 0 {
		cfg.Local.MaxConcurrentLocal = 1
	}
	if cfg.Server.StreamIdleTimeoutMs <= 0 {
		cfg.Server.StreamIdleTimeoutMs = 300000
	}
	if cfg.Local.TTFTTimeoutMs <= 0 {
		cfg.Local.TTFTTimeoutMs = 3500
	}
	if cfg.Contract.MaxRepairAttempts < 0 {
		cfg.Contract.MaxRepairAttempts = 0
	} else if cfg.Contract.MaxRepairAttempts > 1 {
		// Strict contract enforces at most 1 repair attempt
		cfg.Contract.MaxRepairAttempts = 1
	}
	if cfg.Audit.BatchSize <= 0 {
		cfg.Audit.BatchSize = 50
	}
	if cfg.Audit.FlushIntervalMs <= 0 {
		cfg.Audit.FlushIntervalMs = 1000
	}
	if cfg.Audit.QueueSize <= 0 {
		cfg.Audit.QueueSize = 10000
	}
	if cfg.Audit.SQLitePath == "" {
		cfg.Audit.SQLitePath = "data/edgecat_audit.db"
	}
}
