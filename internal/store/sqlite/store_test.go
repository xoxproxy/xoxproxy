package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// newTestDB opens a migrated database in a temp directory.
func newTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestMigrateIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	for i := 0; i < 3; i++ {
		if err := db.Migrate(context.Background()); err != nil {
			t.Fatalf("re-migration %d failed: %v", i, err)
		}
	}
	var version int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("schema version = %d, want 2", version)
	}
	// All v2 tables exist.
	for _, table := range []string{"admin_accounts", "admin_sessions", "audit_logs",
		"users", "credentials", "usage_periods", "destination_stats",
		"configuration_versions", "settings"} {
		var name string
		err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}
}

func TestAdminRepositoryLifecycle(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewAdminRepository(db)

	acc, err := repo.CreateAccount(ctx, store.AdminAccount{
		Username:     "admin",
		PasswordHash: "fake-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if acc.ID == 0 {
		t.Fatal("account ID not set")
	}

	got, err := repo.GetAccountByUsername(ctx, "ADMIN") // case-insensitive
	if err != nil {
		t.Fatalf("case-insensitive lookup failed: %v", err)
	}
	if got.ID != acc.ID {
		t.Fatalf("lookup returned id %d, want %d", got.ID, acc.ID)
	}

	if _, err := repo.GetAccountByUsername(ctx, "ghost"); err != store.ErrNotFound {
		t.Fatalf("missing account error = %v, want ErrNotFound", err)
	}

	// Failure counter round-trips, including lockout.
	lockedUntil := time.Now().UTC().Add(15 * time.Minute)
	if err := repo.RecordLoginFailure(ctx, acc.ID, 5, &lockedUntil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetAccountByID(ctx, acc.ID)
	if got.FailedAttempts != 5 || got.LockedUntil == nil {
		t.Fatalf("failure state = %+v", got)
	}

	if err := repo.ResetFailures(ctx, acc.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetAccountByID(ctx, acc.ID)
	if got.FailedAttempts != 0 || got.LockedUntil != nil {
		t.Fatalf("reset state = %+v", got)
	}

	// UpdatePassword also clears failure state.
	if err := repo.RecordLoginFailure(ctx, acc.ID, 2, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdatePassword(ctx, acc.ID, "new-hash", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetAccountByID(ctx, acc.ID)
	if got.PasswordHash != "new-hash" || got.FailedAttempts != 0 {
		t.Fatalf("password update = %+v", got)
	}

	// Duplicate username is rejected.
	if _, err := repo.CreateAccount(ctx, store.AdminAccount{Username: "admin", PasswordHash: "x"}); err == nil {
		t.Fatal("duplicate username must fail")
	}

	n, err := repo.CountAccounts(ctx)
	if err != nil || n != 1 {
		t.Fatalf("count = %d (%v), want 1", n, err)
	}
}

func TestSessionRepositoryLifecycle(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	admins := NewAdminRepository(db)
	sessions := NewSessionRepository(db)

	acc, err := admins.CreateAccount(ctx, store.AdminAccount{Username: "admin", PasswordHash: "h"})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	s := store.AdminSession{
		ID:         "sess-1",
		AccountID:  acc.ID,
		TokenHash:  "hash-1",
		CSRFToken:  "csrf-1",
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
		LastSeenAt: now,
		SourceIP:   "10.0.0.1",
		UserAgent:  "test",
	}
	if err := sessions.CreateSession(ctx, s); err != nil {
		t.Fatal(err)
	}

	got, err := sessions.GetSessionByTokenHash(ctx, "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != s.ID || got.SourceIP != "10.0.0.1" || got.ExpiresAt.Sub(got.CreatedAt) != time.Hour {
		t.Fatalf("session round-trip mismatch: %+v", got)
	}

	if _, err := sessions.GetSessionByTokenHash(ctx, "nope"); err != store.ErrNotFound {
		t.Fatalf("missing session error = %v", err)
	}

	// Second session for the same account; DeleteSessionsForAccount keeps
	// only the exception.
	s2 := s
	s2.ID, s2.TokenHash = "sess-2", "hash-2"
	if err := sessions.CreateSession(ctx, s2); err != nil {
		t.Fatal(err)
	}
	if err := sessions.DeleteSessionsForAccount(ctx, acc.ID, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.GetSessionByTokenHash(ctx, "hash-1"); err != nil {
		t.Fatalf("kept session deleted: %v", err)
	}
	if _, err := sessions.GetSessionByTokenHash(ctx, "hash-2"); err != store.ErrNotFound {
		t.Fatalf("other session survived: %v", err)
	}

	// Touch + expiry sweep.
	if err := sessions.TouchSession(ctx, "sess-1", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	n, err := sessions.DeleteExpiredSessions(ctx, now.Add(2*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("expired sweep removed %d (%v), want 1", n, err)
	}
	if _, err := sessions.GetSessionByTokenHash(ctx, "hash-1"); err != store.ErrNotFound {
		t.Fatalf("expired session still present: %v", err)
	}
}

func TestAuditRepository(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	audit := NewAuditRepository(db)

	for i := 0; i < 5; i++ {
		if err := audit.Record(ctx, store.AuditEntry{
			Timestamp: time.Now().UTC(),
			Actor:     "admin",
			Action:    "admin.login",
			Result:    "success",
			SourceIP:  "10.0.0.1",
		}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := audit.List(ctx, store.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("got %d entries, want 5", len(entries))
	}
	// Newest first.
	if entries[0].ID < entries[4].ID {
		t.Fatal("entries not ordered newest-first")
	}

	// Cursor pagination: entries older than the third entry's ID.
	cur := entries[2].ID
	page, err := audit.List(ctx, store.AuditFilter{BeforeID: cur, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("cursor page size = %d, want 2", len(page))
	}
	if page[0].ID >= cur {
		t.Fatal("cursor page contains entries at/after cursor")
	}

	// Action filter.
	filtered, err := audit.List(ctx, store.AuditFilter{Action: "user.created", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 0 {
		t.Fatalf("action filter returned %d entries, want 0", len(filtered))
	}
}

func TestAuditDetailIsBounded(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	audit := NewAuditRepository(db)
	long := make([]byte, maxAuditDetail+500)
	for i := range long {
		long[i] = 'x'
	}
	if err := audit.Record(ctx, store.AuditEntry{
		Actor: "admin", Action: "test.bound", Result: "success", Detail: string(long),
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := audit.List(ctx, store.AuditFilter{Limit: 1})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if len(entries[0].Detail) != maxAuditDetail {
		t.Fatalf("detail length = %d, want %d", len(entries[0].Detail), maxAuditDetail)
	}
}
