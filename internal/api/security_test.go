package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// urlEscape encodes hostile payloads safely into query strings.
func urlEscape(s string) string { return url.QueryEscape(s) }

// This file is the automated attack-case suite required by
// docs/SECURITY-TESTING.md. Every test here sends hostile input directly to
// the HTTP layer — no UI involved — because all controls must hold for
// crafted requests. Tests are named TestSecurity* so
// `go test -run TestSecurity ./...` (make test-security) runs exactly this
// suite in CI.
//
// Categories without API surface yet (path traversal, command injection,
// SSRF, IDOR) get their attack suites in the phase that introduces the
// surface; the matrix in docs/SECURITY-TESTING.md tracks this.

// sqlPayloads are classic first- and second-order injection attempts aimed
// at every string that reaches a query.
var sqlPayloads = []string{
	"admin' OR '1'='1",
	"admin'; DROP TABLE admin_sessions; --",
	"admin' UNION SELECT password_hash FROM admin_accounts --",
	"\"; DELETE FROM audit_logs WHERE '1'='1",
	"' OR 1=1 --",
	"admin\"); ATTACH DATABASE '/tmp/evil.db' AS evil; --",
}

func TestSecuritySQLiLoginFields(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	for _, p := range sqlPayloads {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, postJSON("/api/v1/auth/login",
			map[string]string{"username": p, "password": p}))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("payload %q = %d, want 401", p, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "error executing") ||
			strings.Contains(strings.ToLower(rec.Body.String()), "sql") {
			t.Fatalf("payload %q leaked SQL error: %s", p, rec.Body.String())
		}
	}
	// Second-order check: the database is intact — the real account still
	// authenticates after the attack run.
	if _, csrf := login(t, h); csrf == "" {
		t.Fatal("database corrupted by injection attempts")
	}
}

func TestSecuritySQLiQueryParameters(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()
	cookie, csrf := login(t, h)

	for _, p := range []string{
		"1 OR 1=1", "1; DROP TABLE audit_logs", "-1 UNION SELECT 1",
		"9999999999999999999999", "abc", "1e10", "0x10", "١٢٣", "1'",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authed(http.MethodGet,
			"/api/v1/audit-logs?limit="+urlEscape(p), cookie, csrf, nil))
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusOK {
			t.Fatalf("limit payload %q = %d with body %s", p, rec.Code, rec.Body.String())
		}
		if strings.Contains(strings.ToLower(rec.Body.String()), "sql") &&
			!strings.Contains(rec.Body.String(), `"code"`) {
			t.Fatalf("payload %q leaked SQL error: %s", p, rec.Body.String())
		}
	}
	// Same for the action filter.
	for _, p := range sqlPayloads {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authed(http.MethodGet,
			"/api/v1/audit-logs?action="+urlEscape(p), cookie, csrf, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("action payload %q = %d: %s", p, rec.Code, rec.Body.String())
		}
	}
	// The audit table survived.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/audit-logs?limit=1", cookie, csrf, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list broken after attacks: %d", rec.Code)
	}
}

func TestSecurityXSSNotReflected(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	payloads := []string{
		"<script>alert(1)</script>",
		"\"><img src=x onerror=alert(1)>",
		"'-alert(1)-'", "</textarea><script>fetch('//evil')</script>",
	}
	for _, p := range payloads {
		// Reflected: login responses must not echo attacker input.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, postJSON("/api/v1/auth/login",
			map[string]string{"username": p, "password": "whatever-long"}))
		if strings.Contains(rec.Body.String(), "<script>") ||
			strings.Contains(rec.Body.String(), "onerror") {
			t.Fatalf("XSS payload reflected in login response: %s", rec.Body.String())
		}
	}
	// Responses are JSON with nosniff; the browser must not sniff HTML.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff header missing")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("health content type = %q", ct)
	}
}

func TestSecurityAuthBypass(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	protected := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/auth/session"},
		{http.MethodGet, "/api/v1/audit-logs"},
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodPost, "/api/v1/auth/password"},
	}

	mk := func(name, value string, header func(*http.Request)) *http.Request {
		for _, p := range protected {
			r := httptest.NewRequest(p.method, p.path, nil)
			if name != "" {
				r.AddCookie(&http.Cookie{Name: name, Value: value})
			}
			if header != nil {
				header(r)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s with %s cookie = %d, want 401",
					p.method, p.path, description(name, value), rec.Code)
			}
		}
		return nil
	}

	mk("", "", nil)                                 // no cookie at all
	mk(sessionCookie, "", nil)                      // empty value
	mk(sessionCookie, "totally-made-up-token", nil) // unknown token
	mk(sessionCookie, "x", func(r *http.Request) {  // header spoofing
		r.Header.Set("X-CSRF-Token", "x")
		r.Header.Set("Authorization", "Bearer admin")
	})
	mk("othersession", "real-looking-but-wrong", nil) // wrong cookie name

	// A valid session token does not grant mutation access without the
	// CSRF token (covered in depth in TestCSRFEnforced; asserted here as
	// part of the bypass matrix).
	cookie, _ := login(t, h)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/auth/password", cookie, "", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("password change without CSRF = %d, want 403", rec.Code)
	}
}

func description(name, value string) string {
	if name == "" {
		return "no"
	}
	if len(value) > 12 {
		value = value[:12] + "..."
	}
	return name + "=" + value
}

func TestSecuritySessionFixation(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	// An attacker-chosen cookie value must never become valid by logging
	// in: the server mints a fresh token and ignores any client-supplied
	// session value.
	fixed := "attacker-chosen-session-token"
	rec := httptest.NewRecorder()
	r := postJSON("/api/v1/auth/login", map[string]string{
		"username": "admin", "password": testPassword,
	})
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: fixed})
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value == fixed {
			t.Fatal("server accepted attacker-chosen session ID (fixation)")
		}
	}

	// The old value is not valid on its own.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/auth/session", fixed, "", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("attacker-chosen session ID authenticated after victim login")
	}
}

func TestSecurityNoGetMutations(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()
	cookie, csrf := login(t, h)

	// State changes must not be reachable via GET (bypasses CSRF by
	// design). The router rejects wrong methods per route.
	for _, path := range []string{"/api/v1/auth/logout", "/api/v1/auth/password"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authed(http.MethodGet, path, cookie, csrf, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d, want 405", path, rec.Code)
		}
	}
}

func TestSecurityOversizedAndMalformedFields(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	// Field-level bombs inside a valid JSON body of legal size.
	big := strings.Repeat("A", 10_000)
	for _, body := range []map[string]string{
		{"username": big, "password": "x"},
		{"username": "admin", "password": big},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, postJSON("/api/v1/auth/login", body))
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusBadRequest {
			t.Fatalf("oversized field login = %d, want 401/400", rec.Code)
		}
	}

	// Deeply nested JSON (decoder bomb within body cap).
	deep := strings.Repeat(`{"a":`, 1000) + "1" + strings.Repeat("}", 1000)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(deep))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("nested bomb = %d, want 400", rec.Code)
	}

	// Duplicate JSON keys: the decoder takes the last value; no crash and
	// no bypass either way.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postJSONRaw(`{"username":"admin","username":"ghost","password":"x"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate keys = %d, want 401", rec.Code)
	}
}

func postJSONRaw(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestSecurityAuditTrailRecordsAttacks(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	// Attack first, authenticate later; then verify the trail.
	bad := httptest.NewRecorder()
	h.ServeHTTP(bad, postJSON("/api/v1/auth/login",
		map[string]string{"username": "admin", "password": "wrong-guess-123"}))

	cookie, csrf := login(t, h)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet,
		"/api/v1/audit-logs?limit=50&action=admin.login", cookie, csrf, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list = %d", rec.Code)
	}
	var list struct {
		Entries []struct {
			Result string `json:"result"`
			Detail string `json:"detail"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	var sawFailure, sawSuccess bool
	for _, e := range list.Entries {
		if e.Result == "failure" {
			sawFailure = true
			// The failure detail must not contain the attempted
			// password or anything secret-shaped.
			if strings.Contains(e.Detail, "wrong-guess-123") {
				t.Fatal("audit detail contains attempted password")
			}
		}
		if e.Result == "success" {
			sawSuccess = true
		}
	}
	if !sawFailure || !sawSuccess {
		t.Fatalf("audit trail incomplete: failure=%v success=%v", sawFailure, sawSuccess)
	}
}

func TestSecurityReadinessDoesNotLeakInternals(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	srv.AddReadinessCheck("database", func(context.Context) error {
		return context.DeadlineExceeded
	})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if strings.Contains(rec.Body.String(), "context deadline") {
		t.Fatalf("internal error text leaked: %s", rec.Body.String())
	}
}
