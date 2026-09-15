package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/auth"
	"github.com/xoxproxy/xoxproxy/internal/deploy"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// newDeployTestServer wires a server whose deploy service is retrievable,
// so functional tests can drive DeployNow directly and poll its effects.
func newDeployTestServer(t *testing.T) (*deploy.Service, http.Handler, func()) {
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
	// Production wiring: user mutations trigger the pipeline.
	usersSvc.SetStateChangeHook(deploySvc.Trigger)
	srv := NewServer(logger, authSvc, auditSvc, usersSvc, deploySvc, nil, nil, Options{})
	srv.limiter = newRateLimiter(1000, 10000)
	return deploySvc, srv.Handler(), cleanup
}

// TestSecurityDeployRoutes: the deploy-pipeline routes must enforce
// session authentication and CSRF server-side, and crafted query values
// must never yield internals (docs/SECURITY-TESTING.md §5 discipline
// applied to the Phase 6 surface).
func TestSecurityDeployRoutes(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()
	h := srv.Handler()

	readRoutes := []string{"/api/v1/config-versions", "/api/v1/engine/status"}
	for _, target := range readRoutes {
		for name, build := range map[string]func() *http.Request{
			"no cookie": func() *http.Request {
				return httptest.NewRequest(http.MethodGet, target, nil)
			},
			"forged token": func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, target, nil)
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "forged"})
				return r
			},
			"spoofed headers": func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, target, nil)
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "forged"})
				r.Header.Set("Authorization", "Bearer admin")
				r.Header.Set("X-CSRF-Token", "forged")
				return r
			},
		} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, build())
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("GET %s (%s) = %d, want 401", target, name, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "revision") {
				t.Errorf("GET %s (%s) leaked version data: %s", target, name, rec.Body.String())
			}
		}
	}

	// Manual deploy is a mutation: 401 unauthenticated, 403 without CSRF.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/deploy", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/deploy without cookie = %d, want 401", rec.Code)
	}

	cookie, csrf := login(t, h)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/deploy", cookie, "", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /api/v1/deploy without CSRF = %d, want 403", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/deploy", cookie, csrf, nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/v1/deploy = %d: %s", rec.Code, rec.Body.String())
	}

	// Crafted limit values: 400, never internals. ("1%3BDROP" decodes to
	// "1;DROP" inside the handler, where Atoi rejects it; a raw ";"
	// is dropped by the URL query parser before the handler sees it.)
	for _, limit := range []string{"0", "-1", "abc", "9999", "1e3", "1%3BDROP", "%27%20OR%201%3D1"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/config-versions?limit="+limit, cookie, csrf, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit %q = %d (%s), want 400", limit, rec.Code, rec.Body.String())
		}
	}
}

// TestDeployEndpointsFunctional: version history and engine status report
// the pipeline's records, with no credential material anywhere.
func TestDeployEndpointsFunctional(t *testing.T) {
	deploySvc, h, cleanup := newDeployTestServer(t)
	defer cleanup()

	// Seed history the way the server does at boot.
	if _, err := deploySvc.DeployNow(context.Background(), "system", "startup"); err != nil {
		t.Fatal(err)
	}
	// Seed a proxy user so the derived state contains hash-bearing rows.
	// (The fake deployer never renders, but the invariant under test is
	// that even if it did, no hash material reaches these responses.)
	cookie, csrf := login(t, h)
	createUserViaAPI(t, h, cookie, csrf, "alice")
	if _, err := deploySvc.DeployNow(context.Background(), "admin", "user.create:alice"); err != nil {
		t.Fatal(err)
	}

	// Config version history: newest first, both generations present.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/config-versions?limit=10", cookie, csrf, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("config versions = %d: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Versions []struct {
			Revision         int64  `json:"revision"`
			GeneratedBy      string `json:"generated_by"`
			Reason           string `json:"reason"`
			DeploymentStatus string `json:"deployment_status"`
			Checksum         string `json:"checksum"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Versions) != 2 {
		t.Fatalf("got %d versions, want 2: %s", len(list.Versions), rec.Body.String())
	}
	if list.Versions[0].Revision <= list.Versions[1].Revision {
		t.Fatal("versions not newest-first")
	}
	if list.Versions[0].Reason != "user.create:alice" || list.Versions[1].Reason != "startup" {
		t.Fatalf("reasons wrong: %+v", list.Versions)
	}

	// Engine status: running flag (fake engine: not running) + last deploy.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet, "/api/v1/engine/status", cookie, csrf, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("engine status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"running":false`) || !strings.Contains(body, `"last_deploy"`) {
		t.Fatalf("engine status body wrong: %s", body)
	}

	// No credential material in any deploy-pipeline response.
	for _, target := range []string{"/api/v1/config-versions?limit=10", "/api/v1/engine/status"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, authed(http.MethodGet, target, cookie, csrf, nil))
		for _, secret := range []string{"$3$", "argon2id", "CL:", "engine_hash", "api_hash"} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("GET %s exposed %q: %s", target, secret, rec.Body.String())
			}
		}
	}
}

// TestUserMutationTriggersDeploy: an API user mutation reaches the deploy
// pipeline (coalesced) without the HTTP request blocking on it.
func TestUserMutationTriggersDeploy(t *testing.T) {
	deploySvc, h, cleanup := newDeployTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go deploySvc.Start(ctx)

	cookie, csrf := login(t, h)
	createUserViaAPI(t, h, cookie, csrf, "alice")

	// The triggered deploy lands in the version history shortly.
	deadline := time.Now().Add(5 * time.Second)
	for {
		versions, err := deploySvc.ListVersions(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(versions) > 0 && versions[0].Reason == "user.create:alice" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("user mutation never reached the deploy pipeline: %+v", versions)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
