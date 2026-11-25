package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patchcat-dev/edgecat/internal/config"
)

func TestRunInit_ModesAndOverwriteGuard(t *testing.T) {
	tmp := t.TempDir()

	// 1. Default workstation mode
	localOut := filepath.Join(tmp, "workstation.yaml")
	var out, errBuf bytes.Buffer
	if code := runInit([]string{"-out", localOut}, &out, &errBuf); code != 0 {
		t.Fatalf("runInit workstation failed (code %d): %s", code, errBuf.String())
	}
	cfg, err := config.LoadConfig(localOut)
	if err != nil {
		t.Fatalf("LoadConfig on workstation.yaml failed: %v", err)
	}
	if cfg.Server.Host != "127.0.0.1" || cfg.Auth.Enabled {
		t.Fatalf("unexpected workstation config: host=%q auth=%v", cfg.Server.Host, cfg.Auth.Enabled)
	}

	// 2. Refuses overwrite without -force
	errBuf.Reset()
	if code := runInit([]string{"-out", localOut}, &out, &errBuf); code == 0 {
		t.Fatal("expected runInit to refuse overwriting existing file without -force")
	}

	// 3. Overwrite with -lan -force generates cryptographic tokens & passes Fail-Closed guard
	out.Reset()
	errBuf.Reset()
	if code := runInit([]string{"-out", localOut, "-lan", "-force"}, &out, &errBuf); code != 0 {
		t.Fatalf("runInit -lan -force failed (code %d): %s", code, errBuf.String())
	}
	lanCfg, err := config.LoadConfig(localOut)
	if err != nil {
		t.Fatalf("LoadConfig on lan yaml failed: %v", err)
	}
	if lanCfg.Server.Host != "0.0.0.0" || !lanCfg.Auth.Enabled || len(lanCfg.Auth.Clients) != 2 {
		t.Fatalf("unexpected lan config: %+v", lanCfg)
	}
	if !strings.HasPrefix(lanCfg.Auth.Clients[0].Token, "ec-") || len(lanCfg.Auth.Clients[0].Token) != 35 {
		t.Fatalf("expected 35-char random ec- token, got %q", lanCfg.Auth.Clients[0].Token)
	}
	if lanCfg.Auth.Clients[0].Token == lanCfg.Auth.Clients[1].Token {
		t.Fatal("expected distinct tokens per client")
	}

	// 4. Docker mode sets container paths
	dockerOut := filepath.Join(tmp, "docker.yaml")
	if code := runInit([]string{"-out", dockerOut, "-docker"}, &out, &errBuf); code != 0 {
		t.Fatalf("runInit -docker failed (code %d): %s", code, errBuf.String())
	}
	dockerCfg, err := config.LoadConfig(dockerOut)
	if err != nil {
		t.Fatalf("LoadConfig on docker.yaml failed: %v", err)
	}
	if dockerCfg.Audit.SQLitePath != "/var/lib/edgecat/edgecat_audit.db" {
		t.Fatalf("unexpected docker audit path: %q", dockerCfg.Audit.SQLitePath)
	}
}

func TestRunCheck_OfflineAndLiveProbes(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "edgecat.yaml")
	var out, errBuf bytes.Buffer
	if code := runInit([]string{"-out", cfgPath}, &out, &errBuf); code != 0 {
		t.Fatalf("init failed: %s", errBuf.String())
	}

	// Rewrite audit.sqlite_path inside temp dir so test stays hermetic
	raw, _ := os.ReadFile(cfgPath)
	updated := strings.ReplaceAll(string(raw), `"data/edgecat_audit.db"`, `"`+filepath.ToSlash(filepath.Join(tmp, "data", "audit.db"))+`"`)
	_ = os.WriteFile(cfgPath, []byte(updated), 0600)

	// 1. Offline check passes without any live server
	out.Reset()
	errBuf.Reset()
	if code := runCheck([]string{"-config", cfgPath, "-offline"}, &out, &errBuf); code != 0 {
		t.Fatalf("expected offline check to pass, got code %d: %s", code, errBuf.String())
	}

	// 2. Live check with mock Local Tier server passes
	mockOllama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"qwen2.5:7b"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer mockOllama.Close()

	withMock := strings.ReplaceAll(updated, `"http://127.0.0.1:11434/v1"`, `"`+mockOllama.URL+`/v1"`)
	_ = os.WriteFile(cfgPath, []byte(withMock), 0600)

	out.Reset()
	errBuf.Reset()
	if code := runCheck([]string{"-config", cfgPath, "-timeout", "1000"}, &out, &errBuf); code != 0 {
		t.Fatalf("expected live check with mock local tier to pass, got code %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Local Tier reachable") {
		t.Fatalf("expected Local Tier reachable in output, got: %s", out.String())
	}

	// 3. Live check fails when both tiers are unreachable/unconfigured
	dead := strings.ReplaceAll(updated, `"http://127.0.0.1:11434/v1"`, `"http://127.0.0.1:1/v1"`)
	_ = os.WriteFile(cfgPath, []byte(dead), 0600)
	out.Reset()
	errBuf.Reset()
	if code := runCheck([]string{"-config", cfgPath, "-timeout", "300"}, &out, &errBuf); code == 0 {
		t.Fatal("expected live check to return non-zero when neither tier is reachable")
	}
}

func TestRunPing_HealthyAndUnhealthy(t *testing.T) {
	healthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer healthySrv.Close()

	var out, errBuf bytes.Buffer
	if code := runPing([]string{"-url", healthySrv.URL + "/health"}, &out, &errBuf); code != 0 {
		t.Fatalf("expected ping to succeed, got code %d: %s", code, errBuf.String())
	}

	// Verify 0.0.0.0 config resolves to 127.0.0.1
	tmpCfg := filepath.Join(t.TempDir(), "lan.yaml")
	_ = os.WriteFile(tmpCfg, []byte(`
server:
  host: "0.0.0.0"
  port: 18080
auth:
  enabled: true
  clients:
    - name: "a"
      token: "ec-123"
`), 0600)
	u, err := resolveHealthURL(tmpCfg, "")
	if err != nil {
		t.Fatalf("resolveHealthURL failed: %v", err)
	}
	if u != "http://127.0.0.1:18080/health" {
		t.Fatalf("expected http://127.0.0.1:18080/health, got %q", u)
	}

	// Unreachable URL returns exit code 1
	out.Reset()
	errBuf.Reset()
	if code := runPing([]string{"-url", "http://127.0.0.1:1/health", "-timeout", "200"}, &out, &errBuf); code == 0 {
		t.Fatal("expected ping against closed port to fail")
	}
}
