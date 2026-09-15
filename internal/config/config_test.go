package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfig writes a TOML document to a temp file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaultsWhenFileEmpty(t *testing.T) {
	path := writeConfig(t, "")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("empty config should keep defaults, got error: %v", err)
	}
	if cfg.Server.Listen != defaultListenAddr {
		t.Errorf("listen = %q, want %q", cfg.Server.Listen, defaultListenAddr)
	}
	if cfg.Proxy.HTTPPort != 3128 || cfg.Proxy.SOCKS5Port != 1080 {
		t.Errorf("proxy ports = %d/%d, want 3128/1080", cfg.Proxy.HTTPPort, cfg.Proxy.SOCKS5Port)
	}
	if cfg.Engine.Provider != "threeproxy" {
		t.Errorf("provider = %q, want threeproxy", cfg.Engine.Provider)
	}
	d, err := cfg.AnalyticsFlush()
	if err != nil || d != 30*time.Second {
		t.Errorf("flush interval = %v (%v), want 30s", d, err)
	}
}

func TestLoadOverrides(t *testing.T) {
	path := writeConfig(t, `
[server]
listen = "127.0.0.1:9000"

[proxy]
http_port = 13128
socks5_port = 11080
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Proxy.HTTPPort != 13128 || cfg.Proxy.SOCKS5Port != 11080 {
		t.Errorf("ports = %d/%d", cfg.Proxy.HTTPPort, cfg.Proxy.SOCKS5Port)
	}
	// Untouched sections keep defaults.
	if cfg.Database.Path != defaultDBPath {
		t.Errorf("database.path = %q, want default %q", cfg.Database.Path, defaultDBPath)
	}
}

func TestValidateRejectsBadConfigs(t *testing.T) {
	cases := []struct {
		name    string
		toml    string
		wantErr string
	}{
		{
			name:    "bare listen port",
			toml:    "[server]\nlisten = \"8080\"\n",
			wantErr: "must bind an explicit address",
		},
		{
			name:    "same http and socks5 port",
			toml:    "[proxy]\nhttp_port = 3128\nsocks5_port = 3128\n",
			wantErr: "must differ",
		},
		{
			name:    "privileged engine port",
			toml:    "[proxy]\nhttp_port = 80\nsocks5_port = 1080\n",
			wantErr: "cannot bind ports < 1024",
		},
		{
			name:    "port out of range",
			toml:    "[proxy]\nhttp_port = 70000\nsocks5_port = 1080\n",
			wantErr: "1-65535",
		},
		{
			name:    "relative database path",
			toml:    "[database]\npath = \"data/xoxproxy.db\"\n",
			wantErr: "absolute path",
		},
		{
			name:    "unknown provider",
			toml:    "[engine]\nprovider = \"nginx\"\n",
			wantErr: "is not one of threeproxy",
		},
		{
			name:    "bad log level",
			toml:    "[log]\nlevel = \"verbose\"\n",
			wantErr: "debug, info, warn, error",
		},
		{
			name:    "bad duration",
			toml:    "[analytics]\nflush_interval = \"fast\"\n",
			wantErr: "flush_interval",
		},
		{
			name:    "zero queue size",
			toml:    "[analytics]\nqueue_size = 0\n",
			wantErr: "queue_size",
		},
		{
			name:    "public base url with path",
			toml:    "[server]\npublic_base_url = \"https://x.example.com/dash\"\n",
			wantErr: "origin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.toml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateReportsAllErrorsAtOnce(t *testing.T) {
	path := writeConfig(t, "[proxy]\nhttp_port = 3128\nsocks5_port = 3128\n[log]\nlevel = \"loud\"\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "must differ") || !strings.Contains(err.Error(), "debug, info") {
		t.Fatalf("expected joined errors, got: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestDefaultsAreValid(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("built-in defaults must validate: %v", err)
	}
}
