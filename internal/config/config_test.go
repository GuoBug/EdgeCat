package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/patchcat-dev/edgecat/internal/config"
)

func TestValidate_FailClosedLANGuard(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(cfg *config.Config)
		expectErr bool
	}{
		{
			name: "default loopback without auth is valid",
			mutate: func(cfg *config.Config) {
				cfg.Server.Host = "127.0.0.1"
				cfg.Auth.Enabled = false
			},
			expectErr: false,
		},
		{
			name: "localhost without auth is valid",
			mutate: func(cfg *config.Config) {
				cfg.Server.Host = "localhost"
				cfg.Auth.Enabled = false
			},
			expectErr: false,
		},
		{
			name: "0.0.0.0 without auth fails",
			mutate: func(cfg *config.Config) {
				cfg.Server.Host = "0.0.0.0"
				cfg.Auth.Enabled = false
			},
			expectErr: true,
		},
		{
			name: "LAN IP without auth fails",
			mutate: func(cfg *config.Config) {
				cfg.Server.Host = "192.168.1.100"
				cfg.Auth.Enabled = false
			},
			expectErr: true,
		},
		{
			name: "0.0.0.0 with auth enabled but empty clients fails",
			mutate: func(cfg *config.Config) {
				cfg.Server.Host = "0.0.0.0"
				cfg.Auth.Enabled = true
				cfg.Auth.Clients = []config.ClientConfig{}
			},
			expectErr: true,
		},
		{
			name: "0.0.0.0 with auth enabled and valid client succeeds",
			mutate: func(cfg *config.Config) {
				cfg.Server.Host = "0.0.0.0"
				cfg.Auth.Enabled = true
				cfg.Auth.Clients = []config.ClientConfig{
					{Name: "macbook", Token: "ec-token-123"},
				}
			},
			expectErr: false,
		},
		{
			name: "0.0.0.0 without auth but allow_insecure_lan=true succeeds",
			mutate: func(cfg *config.Config) {
				cfg.Server.Host = "0.0.0.0"
				cfg.Auth.Enabled = false
				cfg.Server.AllowInsecureLAN = true
			},
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			tc.mutate(cfg)
			err := config.Validate(cfg)
			if tc.expectErr && err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestLoadConfig_EnvExpansionAndPIIPolicyValidation(t *testing.T) {
	t.Setenv("EDGECAT_TEST_CLOUD_KEY", "sk-from-env-123456")
	cfgPath := filepath.Join(t.TempDir(), "edgecat.yaml")
	yamlBody := `
server:
  host: "127.0.0.1"
cloud:
  api_key: "${EDGECAT_TEST_CLOUD_KEY}"
filter:
  enabled: true
  policy: "mask_on_egress"
`
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if cfg.Cloud.APIKey != "sk-from-env-123456" {
		t.Fatalf("expected env expanded api_key, got %q", cfg.Cloud.APIKey)
	}
	if cfg.Filter.Policy != "mask_on_egress" {
		t.Fatalf("expected mask_on_egress, got %q", cfg.Filter.Policy)
	}

	// Invalid policy must fail validation
	cfg.Filter.Policy = "invalid_policy"
	if err := config.Validate(cfg); err == nil {
		t.Fatal("expected validation error for invalid filter.policy")
	}
}

func TestLoadConfig_ExtendedEnvFallbackAndUnresolvedGuard(t *testing.T) {
	t.Setenv("EDGECAT_TEST_HMAC", "super-secret-hmac-key")
	t.Setenv("EDGECAT_TEST_CLIENT_TOKEN", "ec-real-token-xyz")

	cfgPath := filepath.Join(t.TempDir(), "edgecat-docker.yaml")
	yamlBody := `
server:
  host: "0.0.0.0"
auth:
  enabled: true
  clients:
    - name: "nas-client"
      token: "${EDGECAT_TEST_CLIENT_TOKEN}"
local:
  endpoint: "${EDGECAT_UNSET_LOCAL_URL:-http://host.docker.internal:11434/v1}"
cloud:
  api_key: "${EDGECAT_UNSET_CLOUD_KEY:-}"
filter:
  enabled: true
  hmac_secret: "${EDGECAT_TEST_HMAC}"
`
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("expected valid docker config, got %v", err)
	}
	if cfg.Local.Endpoint != "http://host.docker.internal:11434/v1" {
		t.Fatalf("expected fallback local endpoint, got %q", cfg.Local.Endpoint)
	}
	if cfg.Cloud.APIKey != "" {
		t.Fatalf("expected empty fallback cloud api_key, got %q", cfg.Cloud.APIKey)
	}
	if cfg.Filter.HMACSecret != "super-secret-hmac-key" {
		t.Fatalf("expected expanded hmac_secret, got %q", cfg.Filter.HMACSecret)
	}
	if cfg.Auth.Clients[0].Token != "ec-real-token-xyz" {
		t.Fatalf("expected expanded client token, got %q", cfg.Auth.Clients[0].Token)
	}

	// Unresolved ${VAR} in auth token must fail-closed instead of authenticating literal "${VAR}"
	badPath := filepath.Join(t.TempDir(), "edgecat-bad.yaml")
	badYAML := `
server:
  host: "0.0.0.0"
auth:
  enabled: true
  clients:
    - name: "nas-client"
      token: "${EDGECAT_MISSING_REQUIRED_TOKEN}"
`
	if err := os.WriteFile(badPath, []byte(badYAML), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadConfig(badPath); err == nil {
		t.Fatal("expected fail-closed error when auth client token has unresolved env var")
	}
}
