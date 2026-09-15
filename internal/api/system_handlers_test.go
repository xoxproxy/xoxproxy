package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xoxproxy/xoxproxy/internal/system"
)

// fakeSystem is a canned SystemProvider.
type fakeSystem struct {
	identity  system.Identity
	resources system.Resources
	idErr     error
	resErr    error
}

func (f *fakeSystem) Identity(ctx context.Context) (system.Identity, error) {
	return f.identity, f.idErr
}
func (f *fakeSystem) Resources(ctx context.Context) (system.Resources, error) {
	return f.resources, f.resErr
}

// newSystemTestServer returns a logged-in server with the fake system
// provider wired in.
func newSystemTestServer(t *testing.T, sys *fakeSystem) (*Server, http.Handler, string, string) {
	t.Helper()
	srv, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	srv.system = sys
	h := srv.Handler()
	cookie, csrf := login(t, h)
	return srv, h, cookie, csrf
}

func TestSystemRoutesRequireSession(t *testing.T) {
	srv, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	srv.system = &fakeSystem{}
	h := srv.Handler()
	for _, path := range []string{"/api/v1/system/status", "/api/v1/system/resources"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s without session = %d, want 401", path, rec.Code)
		}
	}
}

func TestSystemDisabledWhenProviderMissing(t *testing.T) {
	srv, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	srv.system = nil
	h := srv.Handler()
	cookie, _ := login(t, h)
	for _, path := range []string{"/api/v1/system/status", "/api/v1/system/resources"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s without provider = %d, want 503", path, rec.Code)
		}
	}
}

func TestSystemStatusHandler(t *testing.T) {
	srv, h, cookie, csrf := newSystemTestServer(t, &fakeSystem{
		identity: system.Identity{
			Hostname: "vps-1", OS: "linux", Platform: "debian 12",
			Kernel: "6.1.0", Arch: "amd64", UptimeSec: 3600,
		},
	})
	srv.SetDeploymentInfo(DeploymentInfo{
		HTTPPort: 3128, SOCKS5Port: 1080, TLS: true,
		PublicIP: func(ctx context.Context) string { return "203.0.113.7" },
	})

	req := authed(http.MethodGet, "/api/v1/system/status", cookie, csrf, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Hostname      string `json:"hostname"`
		Kernel        string `json:"kernel"`
		UptimeSeconds uint64 `json:"uptime_seconds"`
		PublicIP      string `json:"public_ip"`
		EngineRunning bool   `json:"engine_running"`
		ProxyPorts    struct {
			HTTP   int `json:"http"`
			SOCKS5 int `json:"socks5"`
		} `json:"proxy_ports"`
		TLSEnabled bool   `json:"tls_enabled"`
		Version    string `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Hostname != "vps-1" || resp.Kernel != "6.1.0" || resp.UptimeSeconds != 3600 {
		t.Fatalf("identity fields = %+v", resp)
	}
	if resp.PublicIP != "203.0.113.7" {
		t.Fatalf("public ip = %q", resp.PublicIP)
	}
	if resp.ProxyPorts.HTTP != 3128 || resp.ProxyPorts.SOCKS5 != 1080 {
		t.Fatalf("ports = %+v", resp.ProxyPorts)
	}
	if !resp.TLSEnabled {
		t.Fatal("tls flag not carried")
	}
	if resp.Version == "" {
		t.Fatal("version missing")
	}
}

func TestSystemResourcesHandler(t *testing.T) {
	_, h, cookie, csrf := newSystemTestServer(t, &fakeSystem{
		resources: system.Resources{
			CPUPercent: 12.5, Cores: 2, MemTotal: 1000, MemUsed: 400,
			DiskTotal: 20000, DiskUsed: 8000, NetRxBytes: 5, NetTxBytes: 6,
		},
	})
	req := authed(http.MethodGet, "/api/v1/system/resources", cookie, csrf, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("resources = %d", rec.Code)
	}
	var res system.Resources
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.CPUPercent != 12.5 || res.MemTotal != 1000 || res.DiskUsed != 8000 || res.Cores != 2 {
		t.Fatalf("resources = %+v", res)
	}
}

func TestSystemHandlerErrorsAreOpaque(t *testing.T) {
	_, h, cookie, csrf := newSystemTestServer(t, &fakeSystem{
		idErr:  errors.New("internal detail /etc/hosts"),
		resErr: errors.New("internal detail"),
	})
	for _, path := range []string{"/api/v1/system/status", "/api/v1/system/resources"} {
		req := authed(http.MethodGet, path, cookie, csrf, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s = %d, want 500", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "/etc/hosts") || strings.Contains(rec.Body.String(), "internal detail") {
			t.Fatalf("%s leaked internals: %s", path, rec.Body.String())
		}
	}
}
