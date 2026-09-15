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
	"github.com/xoxproxy/xoxproxy/internal/store"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// newResetTestServer wires a server like newTestServer but keeps the DB
// handle so the ledger can be seeded and inspected directly.
func newResetTestServer(t *testing.T) (*Server, *sqlite.DB, http.Handler, string, string) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
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
	usersSvc.SetUsageResetter(sqlite.NewAnalyticsRepository(db))
	deploySvc := deploy.NewService(logger,
		newFakeDeployer(),
		deploy.UsersStateSource(sqlite.NewUserRepository(db)),
		sqlite.NewConfigVersionRepository(db),
		auditSvc)
	srv := NewServer(logger, authSvc, auditSvc, usersSvc, deploySvc, nil, nil, Options{})
	h := srv.Handler()
	cookie, csrf := login(t, h)
	return srv, db, h, cookie, csrf
}

// seedUsage adds one flush batch to the ledger: a day row and a month row
// for the delta's window.
func seedUsage(t *testing.T, repo *sqlite.AnalyticsRepository, userID int64, day, month string, bytes int64) {
	t.Helper()
	err := repo.ApplyDeltas(context.Background(),
		[]store.UsageDelta{{
			UserID: userID, Username: "seed", Day: day, Month: month,
			BytesIn: bytes, BytesOut: bytes / 2, Connections: 1,
		}}, nil, store.LogCursor{})
	if err != nil {
		t.Fatal(err)
	}
}

// TestUserResetQuota covers the endpoint contract: session required,
// unknown user 404s, and a successful reset zeroes the current window in
// the usage ledger while leaving older history intact.
func TestUserResetQuota(t *testing.T) {
	_, db, h, cookie, csrf := newResetTestServer(t)
	repo := sqlite.NewAnalyticsRepository(db)

	// Create a user via the API.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost, "/api/v1/users", cookie, csrf,
		strings.NewReader(`{"username":"quotauser","allowed_protocols":["http"]}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID      int64 `json:"id"`
		Version int64 `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	// Seed the ledger: today's window plus an older day.
	now := time.Now().UTC()
	today := now.Format("2006-01-02")
	month := now.Format("2006-01")
	oldDay := now.AddDate(0, 0, -10).Format("2006-01-02")
	seedUsage(t, repo, created.ID, today, month, 1000)
	seedUsage(t, repo, created.ID, oldDay, month, 500)

	// Reset requires the session.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
		"/api/v1/users/"+itoa(created.ID)+"/reset-quota", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated reset = %d", rec.Code)
	}

	// Reset with the version body.
	body := `{"version":` + itoa(created.Version) + `}`
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost,
		"/api/v1/users/"+itoa(created.ID)+"/reset-quota", cookie, csrf,
		strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("reset = %d: %s", rec.Code, rec.Body.String())
	}

	// Today's day row and the month row are gone; the old day survives.
	periods, err := repo.ListUserTraffic(context.Background(), created.ID,
		time.Now().AddDate(0, 0, -30))
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, p := range periods {
		total += p.BytesIn
	}
	if total != 500 {
		t.Fatalf("after reset total bytes = %d, want 500 (old day only)", total)
	}

	// The action was audited with the username as target.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodGet,
		"/api/v1/audit-logs?action=user.reset_quota&limit=10", cookie, csrf, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "quotauser") {
		t.Fatalf("audit missing reset action: %d %s", rec.Code, rec.Body.String())
	}

	// Unknown user: 404.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authed(http.MethodPost,
		"/api/v1/users/99999/reset-quota", cookie, csrf, strings.NewReader(body)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown user reset = %d, want 404", rec.Code)
	}
}
