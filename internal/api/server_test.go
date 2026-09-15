package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/auth"
	"github.com/xoxproxy/xoxproxy/internal/deploy"
	"github.com/xoxproxy/xoxproxy/internal/engine"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// fakeDeployer stands in for the real engine deployer in HTTP tests: it
// accepts every state and reports the engine as not running (the
// "config applies on next start" path).
type fakeDeployer struct{}

func (fakeDeployer) Deploy(ctx context.Context, state engine.State) (deploy.Result, error) {
	return deploy.Result{Changed: true, Checksum: "deadbeef"}, nil
}

func (fakeDeployer) Running() (bool, error) { return false, nil }

func newFakeDeployer() deploy.Deployer { return fakeDeployer{} }

const testPassword = "correct-staple-9x"

// newTestServer wires a full server over a real SQLite store.
func newTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() { db.Close() }
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditSvc := audit.New(logger, sqlite.NewAuditRepository(db))
	authSvc, err := auth.New(logger,
		sqlite.NewAdminRepository(db),
		sqlite.NewSessionRepository(db),
		auditSvc, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authSvc.CreateAccount(context.Background(), "admin", testPassword, "test", ""); err != nil {
		t.Fatal(err)
	}
	usersSvc := users.NewService(logger,
		sqlite.NewUserRepository(db),
		sqlite.NewCredentialRepository(db),
		auditSvc)
	deploySvc := deploy.NewService(logger,
		newFakeDeployer(),
		deploy.UsersStateSource(sqlite.NewUserRepository(db)),
		sqlite.NewConfigVersionRepository(db),
		auditSvc)
	srv := NewServer(logger, authSvc, auditSvc, usersSvc, deploySvc, nil, nil, Options{})
	// The route-matrix security tests issue hundreds of sequential
	// requests from one IP; a load-shedding 429 would mask the auth
	// assertions. Rate limiting itself is covered by
	// TestRateLimitShedsLoad on its own server.
	srv.limiter = newRateLimiter(1000, 10000)
	return srv, cleanup
}

// login authenticates and returns (cookie, csrfToken).
func login(t *testing.T, h http.Handler) (string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/api/v1/auth/login", map[string]string{
		"username": "admin", "password": testPassword,
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var cookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("no session cookie set")
	}
	return cookie, resp.CSRFToken
}

// authed builds a request carrying the session cookie and, for mutations,
// the CSRF header. A non-nil JSON body gets the matching content type.
func authed(method, target, cookie, csrf string, body io.Reader) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, body)
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	return r
}

func jsonBody(v any) io.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

// postJSON builds a POST request with a JSON content type.
func postJSON(target string, v any) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, jsonBody(v))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestHealthEndpoints(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("live = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready = %d, want 200 (no checks yet)", rec.Code)
	}

	// Failing readiness check surfaces as 503 without internals.
	srv.AddReadinessCheck("database", func(context.Context) error {
		return fmt.Errorf("boom")
	})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Fatal("internal error leaked into response")
	}
}

func TestLoginFlow(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	cookie, csrf := login(t, h)

	// Session endpoint requires the cookie.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("session without cookie = %d, want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/auth/session", cookie, csrf, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("session = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"csrf_token"`) {
		t.Fatalf("session response missing csrf: %s", rec.Body.String())
	}
}

func TestLoginFailuresAreUniform(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	attempt := func(user, pass string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, postJSON("/api/v1/auth/login",
			map[string]string{"username": user, "password": pass}))
		return rec
	}

	recs := []*httptest.ResponseRecorder{
		attempt("ghost", "whatever-long-password"),
		attempt("admin", "wrong-password-here"),
		attempt("", "x"),
	}
	for i, rec := range recs {
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "INVALID_CREDENTIALS") {
			t.Fatalf("attempt %d missing code: %s", i, rec.Body.String())
		}
	}
	// Bodies for unknown-user and wrong-password are identical except
	// request_id (which is unique per request by design).
	var e1, e2 errorEnvelope
	if err := json.Unmarshal(recs[0].Body.Bytes(), &e1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(recs[1].Body.Bytes(), &e2); err != nil {
		t.Fatal(err)
	}
	if e1.Error.Code != e2.Error.Code || e1.Error.Message != e2.Error.Message {
		t.Fatalf("failure responses differ:\n%s\n%s", recs[0].Body, recs[1].Body)
	}
	if e1.Error.RequestID == "" || e1.Error.RequestID == e2.Error.RequestID {
		t.Fatal("request IDs must be present and unique")
	}

	// Non-JSON body rejected before auth.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader("username=admin"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form body = %d, want 415", rec.Code)
	}
}

func TestCSRFEnforced(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	cookie, csrf := login(t, h)

	// Mutation without CSRF header.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/auth/logout", cookie, "", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("logout without csrf = %d, want 403", rec.Code)
	}

	// Wrong CSRF.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/auth/logout", cookie, "forged-token", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("logout with forged csrf = %d, want 403", rec.Code)
	}

	// Correct CSRF: logout works and revokes.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/auth/logout", cookie, csrf, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/auth/session", cookie, csrf, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("session after logout = %d, want 401", rec.Code)
	}
}

func TestPasswordChangeFlow(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	cookie, csrf := login(t, h)

	// Second session (another browser).
	cookie2, _ := login(t, h)

	// Weak new password rejected.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/auth/password", cookie, csrf,
		jsonBody(map[string]string{"current_password": testPassword, "new_password": "short"})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("weak password = %d: %s", rec.Code, rec.Body.String())
	}

	// Wrong current password rejected.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/auth/password", cookie, csrf,
		jsonBody(map[string]string{"current_password": "nope-not-it", "new_password": "a-newer-staple-3"})))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current = %d, want 401", rec.Code)
	}

	// Correct change.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/auth/password", cookie, csrf,
		jsonBody(map[string]string{"current_password": testPassword, "new_password": "a-newer-staple-3"})))
	if rec.Code != http.StatusOK {
		t.Fatalf("password change = %d: %s", rec.Code, rec.Body.String())
	}

	// Other session revoked; current session alive.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/auth/session", cookie2, "", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("second session survived: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/auth/session", cookie, "", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("changing session revoked: %d", rec.Code)
	}
}

func TestAuditLogRequiresAuthAndPaginates(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	// Unauthenticated.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("audit without auth = %d", rec.Code)
	}

	cookie, csrf := login(t, h)

	// The login we just did is in the trail.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/audit-logs?limit=10", cookie, csrf, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list = %d: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Entries []struct {
			Action string `json:"action"`
			Result string `json:"result"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range list.Entries {
		if e.Action == "admin.login" && e.Result == "success" {
			found = true
		}
	}
	if !found {
		t.Fatalf("admin.login success not in audit trail: %s", rec.Body.String())
	}

	// Invalid limit rejected.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/audit-logs?limit=9999", cookie, csrf, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad limit = %d, want 400", rec.Code)
	}
}

func TestRateLimitShedsLoad(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	// newTestServer widens the limiter for the route-matrix tests; restore
	// production limits for this test.
	srv.limiter = newRateLimiter(rateLimitRate, rateLimitBurst)
	h := srv.Handler()

	limited := 0
	for i := 0; i < 60; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		if rec.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("rate limiter never engaged after 60 rapid requests")
	}
}

func TestBodySizeBounded(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	// A JSON string prefix that runs past the limit: the decoder hits the
	// cap mid-value rather than failing on syntax first.
	big := append(append([]byte{'"'}, bytes.Repeat([]byte{'a'}, maxBodyBytes+1024)...), '"')
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(big))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d, want 413", rec.Code)
	}
}

func TestSecurityHeadersAndRequestID(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rec.Header().Get("X-Frame-Options") != "DENY" ||
		rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("security headers missing: %v", rec.Header())
	}
	if !strings.HasPrefix(rec.Header().Get(HeaderRequestID), "req_") {
		t.Fatalf("X-Request-ID = %q", rec.Header().Get(HeaderRequestID))
	}
}

func TestUnknownJSONFieldsRejected(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		jsonBody(map[string]string{"username": "admin", "password": testPassword, "extra": "field"}))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/health/live", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /health/live = %d, want 405", rec.Code)
	}
}
