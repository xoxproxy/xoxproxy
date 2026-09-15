package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/analytics"
)

// --- SSE stream ---

func TestStreamRequiresSession(t *testing.T) {
	stub := &stubAnalytics{}
	_, h, _, _ := newAnalyticsTestServer(t, stub)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/analytics/stream", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stream without session = %d, want 401", rec.Code)
	}
}

// flushRecorder is a ResponseRecorder that also satisfies http.Flusher
// (the recorder itself does not, and the SSE handler requires it). Writes
// land immediately, so Flush is a no-op.
type flushRecorder struct {
	*httptest.ResponseRecorder
}

func (f *flushRecorder) Flush() {}

func TestStreamEmitsTicks(t *testing.T) {
	stub := &stubAnalytics{live: analytics.LiveSnapshot{Day: "2026-09-15", Requests: 3}}
	_, h, cookie, _ := newAnalyticsTestServer(t, stub)

	// A client that goes away after reading the priming event: cancel the
	// request context so the handler's loop exits promptly.
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/stream", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := &flushRecorder{httptest.NewRecorder()}

	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, req)
		close(done)
	}()
	// The priming event is written before the first tick wait.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.Body.String(), "event: tick") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	body := rec.Body.String()
	if !strings.Contains(body, "event: tick\ndata: ") {
		t.Fatalf("no tick event in stream: %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type = %q", ct)
	}
	// The payload nests the live snapshot under "analytics".
	type tickPayload struct {
		Analytics analytics.LiveSnapshot `json:"analytics"`
	}
	var payload tickPayload
	line := body[strings.Index(body, "data: ")+6:]
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("tick payload not JSON: %v", err)
	}
	if payload.Analytics.Day != "2026-09-15" || payload.Analytics.Requests != 3 {
		t.Fatalf("payload = %+v", payload)
	}
}

// --- engine log tail ---

func TestEngineLogTail(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "traffic.log")
	lines := "first line\nsecond line\nthird line\n"
	if err := os.WriteFile(logPath, []byte(lines), 0o640); err != nil {
		t.Fatal(err)
	}

	srv, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	srv.SetTrafficLogPath(logPath)
	h := srv.Handler()
	cookie, csrf := login(t, h)

	// Full tail, oldest first.
	req := authed(http.MethodGet, "/api/v1/logs/engine?limit=10", cookie, csrf, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tail = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Lines) != 3 || resp.Lines[0] != "first line" || resp.Lines[2] != "third line" {
		t.Fatalf("lines = %v", resp.Lines)
	}

	// Bounded tail: last N only.
	req = authed(http.MethodGet, "/api/v1/logs/engine?limit=2", cookie, csrf, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Lines) != 2 || resp.Lines[0] != "second line" {
		t.Fatalf("bounded lines = %v", resp.Lines)
	}

	// Bad limit.
	req = authed(http.MethodGet, "/api/v1/logs/engine?limit=0", cookie, csrf, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("limit 0 = %d, want 400", rec.Code)
	}

	// Missing log: empty, not an error.
	srv.SetTrafficLogPath(filepath.Join(dir, "absent.log"))
	req = authed(http.MethodGet, "/api/v1/logs/engine", cookie, csrf, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("absent log = %d, want 200", rec.Code)
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Lines) != 0 {
		t.Fatalf("absent log lines = %v", resp.Lines)
	}

	// Unauthenticated.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/logs/engine", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated tail = %d", rec.Code)
	}
}

// --- dashboard shell ---

func TestDashboardShellServed(t *testing.T) {
	srv, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	h := srv.Handler()

	// Root and deep links render the shell (public).
	for _, path := range []string{"/", "/users", "/analytics/top"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 (shell)", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("GET %s content type = %q", path, ct)
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") {
			t.Fatalf("GET %s CSP = %q", path, csp)
		}
	}

	// API paths never fall through to the shell.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown api = %d, want 404", rec.Code)
	}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatal("api 404 must be JSON, not the shell")
	}

	// Wrong-method API request keeps its 405 (no-GET-mutations guarantee
	// is not weakened by the SPA fallback).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/logout", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout = %d, want 405", rec.Code)
	}

	_ = srv
}
