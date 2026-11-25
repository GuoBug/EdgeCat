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
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var reEnvRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// Config represents the complete gateway runtime configuration.
type Config struct {
	Server   ServerConfig   `yaml:"server" json:"server"`
	Auth     AuthConfig     `yaml:"auth" json:"auth"`
	Local    LocalConfig    `yaml:"local" json:"local"`
	Cloud    CloudConfig    `yaml:"cloud" json:"cloud"`
	Filter   FilterConfig   `yaml:"filter" json:"filter"`
	Contract ContractConfig `yaml:"contract" json:"contract"`
	Audit    AuditConfig    `yaml:"audit" json:"audit"`
	Memory   MemoryConfig   `yaml:"memory" json:"memory"`
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
	StreamIdleTimeoutMs int      `yaml:"stream_idle_timeout_ms" json:"stream_idle_timeout_ms"`
	AllowedOrigins      []string `yaml:"allowed_origins" json:"allowed_origins"`
	AllowInsecureLAN    bool     `yaml:"allow_insecure_lan" json:"allow_insecure_lan"`
	MaxRequestBodyBytes int64    `yaml:"max_request_body_bytes" json:"max_request_body_bytes"`
}

// AuthConfig configures client authentication for multi-device / homelab sharing.
type AuthConfig struct {
	Enabled bool           `yaml:"enabled" json:"enabled"`
	Clients []ClientConfig `yaml:"clients" json:"clients"`
}

// ClientConfig represents an authenticated client (device, user, or companion app).
type ClientConfig struct {
	Name            string `yaml:"name" json:"name"`
	Token           string `yaml:"token" json:"token"`
	DailyCloudLimit int    `yaml:"daily_cloud_limit" json:"daily_cloud_limit"` // 0: unlimited, -1: local only, >0: max daily cloud calls
	PIIPolicy       string `yaml:"pii_policy" json:"pii_policy"`               // optional override: mask_always, mask_on_egress, local_only, block
	QueueWaitMs     int    `yaml:"queue_wait_ms" json:"queue_wait_ms"`         // optional override for local semaphore wait
}

// LocalConfig configures the local inference tier (e.g., Ollama / vLLM / llama.cpp).
type LocalConfig struct {
	Endpoint                string            `yaml:"endpoint" json:"endpoint"`
	APIKey                  string            `yaml:"api_key" json:"api_key"`
	MaxConcurrentLocal      int               `yaml:"max_concurrent_local" json:"max_concurrent_local"`
	QueueWaitMs             int               `yaml:"queue_wait_ms" json:"queue_wait_ms"`
	TTFTTimeoutMs           int               `yaml:"ttft_timeout_ms" json:"ttft_timeout_ms"`
	StreamIdleTimeoutMs     int               `yaml:"stream_idle_timeout_ms" json:"stream_idle_timeout_ms"`
	BreakerFailureThreshold int               `yaml:"breaker_failure_threshold" json:"breaker_failure_threshold"`
	BreakerCooldownMs       int               `yaml:"breaker_cooldown_ms" json:"breaker_cooldown_ms"`
	ModelMapping            map[string]string `yaml:"model_mapping" json:"model_mapping"`
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
	Enabled                  bool   `yaml:"enabled" json:"enabled"`
	Policy                   string `yaml:"policy" json:"policy"` // mask_always (default), mask_on_egress, local_only, block
	MaskPhone                bool   `yaml:"mask_phone" json:"mask_phone"`
	MaskEmail                bool   `yaml:"mask_email" json:"mask_email"`
	MaskIPv4                 bool   `yaml:"mask_ipv4" json:"mask_ipv4"`
	MaskAPIKey               bool   `yaml:"mask_apikey" json:"mask_apikey"`
	MaskIDCard               bool   `yaml:"mask_idcard" json:"mask_idcard"`
	MaskBankCard             bool   `yaml:"mask_bankcard" json:"mask_bankcard"`
	BlockAPIKeyToolRehydrate bool   `yaml:"block_apikey_tool_rehydrate" json:"block_apikey_tool_rehydrate"`
	// HMACSecret optionally upgrades sequential PII placeholders ({{EC_PII_PHONE_1}})
	// to deterministic cross-request HMAC-SHA256 stable keys ({{EC_PII_PHONE_<16hex>}}).
	HMACSecret string `yaml:"hmac_secret" json:"hmac_secret"`
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

// MemoryConfig configures the opt-in layered memory RequestMutator plugin (R3.2 / R3.2.1).
// Disabled by default to preserve EdgeCat's stateless gateway baseline.
type MemoryConfig struct {
	Enabled               bool   `yaml:"enabled" json:"enabled"`
	SQLitePath            string `yaml:"sqlite_path" json:"sqlite_path"`
	MaxPinnedFacts        int    `yaml:"max_pinned_facts" json:"max_pinned_facts"`
	MaxFacts              int    `yaml:"max_facts" json:"max_facts"`
	MaxShortTerm          int    `yaml:"max_short_term" json:"max_short_term"`
	QueryTimeoutMs        int    `yaml:"query_timeout_ms" json:"query_timeout_ms"`
	ReaderMaxOpenConns    int    `yaml:"reader_max_open_conns" json:"reader_max_open_conns"`
	PrependDynamicContext bool   `yaml:"prepend_dynamic_context" json:"prepend_dynamic_context"`
}

// DefaultConfig returns a sane default configuration.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:                "127.0.0.1",
			Port:                8080,
			ReadTimeoutMs:       30000,
			WriteTimeoutMs:      120000,
			StreamIdleTimeoutMs: 300000,
			AllowedOrigins:      []string{},
			AllowInsecureLAN:    false,
			MaxRequestBodyBytes: 10 * 1024 * 1024, // 10MB default limit
		},
		Auth: AuthConfig{
			Enabled: false,
			Clients: []ClientConfig{},
		},
		Local: LocalConfig{
			Endpoint:                "http://127.0.0.1:11434/v1",
			APIKey:                  "",
			MaxConcurrentLocal:      2,
			TTFTTimeoutMs:           3500,
			StreamIdleTimeoutMs:     30000,
			BreakerFailureThreshold: 3,
			BreakerCooldownMs:       30000,
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
			Enabled:                  true,
			Policy:                   "mask_always",
			MaskPhone:                true,
			MaskEmail:                true,
			MaskIPv4:                 true,
			MaskAPIKey:               true,
			MaskIDCard:               false,
			MaskBankCard:             false,
			BlockAPIKeyToolRehydrate: true,
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
		Memory: MemoryConfig{
			Enabled:               false,
			SQLitePath:            "data/edgecat_memory.db",
			MaxPinnedFacts:        10,
			MaxFacts:              5,
			MaxShortTerm:          3,
			QueryTimeoutMs:        50,
			ReaderMaxOpenConns:    4,
			PrependDynamicContext: false,
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
	expandEnvRefs(cfg)
	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	return cfg, nil
}

func expandEnvRefs(cfg *Config) {
	expand := func(s string) string {
		return reEnvRef.ReplaceAllStringFunc(s, func(match string) string {
			sub := reEnvRef.FindStringSubmatch(match)
			if len(sub) >= 2 {
				if val, ok := os.LookupEnv(sub[1]); ok && val != "" {
					return val
				}
				// Support ${VAR:-default} fallback syntax when :- is present in match
				if strings.Contains(match, ":-") && len(sub) >= 3 {
					return sub[2]
				}
			}
			return match
		})
	}
	cfg.Local.Endpoint = expand(cfg.Local.Endpoint)
	cfg.Local.APIKey = expand(cfg.Local.APIKey)
	cfg.Cloud.Endpoint = expand(cfg.Cloud.Endpoint)
	cfg.Cloud.APIKey = expand(cfg.Cloud.APIKey)
	cfg.Filter.HMACSecret = expand(cfg.Filter.HMACSecret)
	cfg.Audit.SQLitePath = expand(cfg.Audit.SQLitePath)
	cfg.Memory.SQLitePath = expand(cfg.Memory.SQLitePath)
	for i := range cfg.Auth.Clients {
		cfg.Auth.Clients[i].Token = expand(cfg.Auth.Clients[i].Token)
	}
}

func isValidPIIPolicy(p string) bool {
	switch p {
	case "", "mask_always", "mask_on_egress", "local_only", "block":
		return true
	default:
		return false
	}
}

// IsLoopbackHost checks whether a host is a local loopback interface.
func IsLoopbackHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

// Validate checks configuration invariants, including the fail-closed LAN guard (R2.1).
func Validate(cfg *Config) error {
	// Fail-closed LAN guard: Non-loopback host must have auth enabled with at least one client,
	// unless explicitly bypassed via AllowInsecureLAN.
	if !IsLoopbackHost(cfg.Server.Host) && !cfg.Server.AllowInsecureLAN {
		if !cfg.Auth.Enabled {
			return fmt.Errorf("fail-closed LAN guard: binding to non-loopback host %q requires auth.enabled=true with at least one client (or set server.allow_insecure_lan=true to bypass)", cfg.Server.Host)
		}
		validClients := 0
		for _, c := range cfg.Auth.Clients {
			if strings.TrimSpace(c.Token) != "" {
				validClients++
			}
		}
		if validClients == 0 {
			return fmt.Errorf("fail-closed LAN guard: binding to non-loopback host %q requires at least one client with a non-empty token in auth.clients", cfg.Server.Host)
		}
	}

	if cfg.Auth.Enabled {
		for i, c := range cfg.Auth.Clients {
			if strings.TrimSpace(c.Token) == "" {
				return fmt.Errorf("auth.clients[%d] token cannot be empty when auth is enabled", i)
			}
			if reEnvRef.MatchString(c.Token) {
				return fmt.Errorf("auth.clients[%d] token contains unresolved environment variable %q", i, c.Token)
			}
			if !isValidPIIPolicy(c.PIIPolicy) {
				return fmt.Errorf("auth.clients[%d] invalid pii_policy %q", i, c.PIIPolicy)
			}
		}
	}

	if reEnvRef.MatchString(cfg.Filter.HMACSecret) {
		return fmt.Errorf("filter.hmac_secret contains unresolved environment variable %q", cfg.Filter.HMACSecret)
	}

	if !isValidPIIPolicy(cfg.Filter.Policy) {
		return fmt.Errorf("filter.policy invalid value %q", cfg.Filter.Policy)
	}

	return nil
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
	if cfg.Server.MaxRequestBodyBytes <= 0 {
		cfg.Server.MaxRequestBodyBytes = 10 * 1024 * 1024
	}
	if cfg.Local.TTFTTimeoutMs <= 0 {
		cfg.Local.TTFTTimeoutMs = 3500
	}
	if cfg.Local.StreamIdleTimeoutMs <= 0 {
		cfg.Local.StreamIdleTimeoutMs = 30000
	}
	if cfg.Local.BreakerFailureThreshold <= 0 {
		cfg.Local.BreakerFailureThreshold = 3
	}
	if cfg.Local.BreakerCooldownMs <= 0 {
		cfg.Local.BreakerCooldownMs = 30000
	}
	if cfg.Filter.Policy == "" {
		cfg.Filter.Policy = "mask_always"
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
	if cfg.Memory.MaxPinnedFacts <= 0 {
		cfg.Memory.MaxPinnedFacts = 10
	}
	if cfg.Memory.MaxFacts <= 0 {
		cfg.Memory.MaxFacts = 5
	}
	if cfg.Memory.MaxShortTerm <= 0 {
		cfg.Memory.MaxShortTerm = 3
	}
	if cfg.Memory.QueryTimeoutMs <= 0 {
		cfg.Memory.QueryTimeoutMs = 50
	}
	if cfg.Memory.ReaderMaxOpenConns <= 0 {
		cfg.Memory.ReaderMaxOpenConns = 4
	}
	if cfg.Memory.SQLitePath == "" {
		cfg.Memory.SQLitePath = "data/edgecat_memory.db"
	}
}
