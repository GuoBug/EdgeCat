package config_test

import (
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
