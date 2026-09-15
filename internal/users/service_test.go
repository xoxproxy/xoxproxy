package users

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/auth"
	"github.com/xoxproxy/xoxproxy/internal/engine"
	"github.com/xoxproxy/xoxproxy/internal/store"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
)

const testPassword = "correct-staple-9x"

func newTestService(t *testing.T) (*Service, *sqlite.DB) {
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
	svc := NewService(logger,
		sqlite.NewUserRepository(db),
		sqlite.NewCredentialRepository(db),
		auditSvc)
	// Distinct generated password per call so rotation tests can tell
	// generations apart.
	n := 0
	svc.generatePassword = func() string {
		n++
		return "generated-staple-42x-" + strconv.Itoa(n)
	}
	return svc, db
}

func validCreate() CreateInput {
	return CreateInput{
		Username:  "alice",
		Protocols: []string{"http", "socks5"},
	}
}

var testActor = Actor{Name: "admin", RequestID: "req_test"}

func TestCreateGeneratesCredentialAndHashes(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()

	user, password, err := svc.Create(ctx, validCreate(), testActor)
	if err != nil {
		t.Fatal(err)
	}
	if password != "generated-staple-42x-1" {
		t.Fatalf("password = %q, want generated value", password)
	}
	if user.Status != store.UserActive || user.Version != 1 {
		t.Fatalf("unexpected user: %+v", user)
	}

	// The stored credential carries both verifiers; the plaintext is
	// nowhere in the database.
	creds := sqlite.NewCredentialRepository(db)
	cred, err := creds.GetActiveForUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cred.EngineHash, "$3$") {
		t.Errorf("engine hash %q is not a $3$ verifier", cred.EngineHash)
	}
	if !strings.HasPrefix(cred.APIHash, "$argon2id$") {
		t.Errorf("api hash %q is not argon2id", cred.APIHash)
	}
	if ok, err := auth.VerifyPassword(password, cred.APIHash); err != nil || !ok {
		t.Errorf("api hash does not verify the password: %v", err)
	}
	if strings.Contains(cred.EngineHash, password) || strings.Contains(cred.APIHash, password) {
		t.Error("plaintext password embedded in a hash")
	}
}

func TestCreateValidation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(24 * time.Hour)
	quota := int64(512 * 1024) // below 1 MiB granularity

	cases := map[string]func(*CreateInput){
		"bad username":     func(in *CreateInput) { in.Username = "bad\nusers root:CL:x" },
		"username xss":     func(in *CreateInput) { in.Username = "<script>alert(1)</script>" },
		"no protocols":     func(in *CreateInput) { in.Protocols = nil },
		"unknown protocol": func(in *CreateInput) { in.Protocols = []string{"http", "ftp"} },
		"protocol injection": func(in *CreateInput) {
			in.Protocols = []string{"http\nallow *"}
		},
		"negative bandwidth": func(in *CreateInput) { in.DownloadBPS = -1 },
		"quota too small":    func(in *CreateInput) { in.QuotaBytesDaily = quota },
		"past expiry":        func(in *CreateInput) { in.ExpiresAt = &past },
		"weak password":      func(in *CreateInput) { in.Password = "alice123" }, // contains username
		"short password":     func(in *CreateInput) { in.Password = "short" },
	}
	for name, mutate := range cases {
		in := validCreate()
		mutate(&in)
		if _, _, err := svc.Create(ctx, in, testActor); err == nil {
			t.Errorf("%s: create accepted invalid input", name)
		}
	}

	// Control: the untouched input is valid, with every optional field set.
	in := validCreate()
	in.DownloadBPS = 20 * 1000 * 1000
	in.UploadBPS = 10 * 1000 * 1000
	in.MaxConnections = 50
	in.QuotaBytesMonthly = 100 * engine.MiB
	in.ExpiresAt = &future
	if _, _, err := svc.Create(ctx, in, testActor); err != nil {
		t.Fatalf("valid create rejected: %v", err)
	}
}

func TestCreateDuplicateUsernameConflicts(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, _, err := svc.Create(ctx, validCreate(), testActor); err != nil {
		t.Fatal(err)
	}
	_, _, err := svc.Create(ctx, validCreate(), testActor)
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("duplicate create = %v, want ErrUsernameTaken", err)
	}
}

func TestUpdateOptimisticLocking(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	user, _, err := svc.Create(ctx, validCreate(), testActor)
	if err != nil {
		t.Fatal(err)
	}

	newQuota := int64(5 * engine.MiB)
	updated, err := svc.Update(ctx, user.ID, UpdateInput{
		Version:           user.Version,
		QuotaBytesMonthly: &newQuota,
	}, testActor)
	if err != nil {
		t.Fatal(err)
	}
	if updated.QuotaBytesMonthly != newQuota || updated.Version != user.Version+1 {
		t.Fatalf("update did not apply: %+v", updated)
	}

	// Stale version is rejected — no lost update.
	if _, err := svc.Update(ctx, user.ID, UpdateInput{
		Version:           user.Version,
		QuotaBytesMonthly: &newQuota,
	}, testActor); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale update = %v, want ErrVersionConflict", err)
	}
}

func TestUpdateExpirationHandling(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Create without expiry, set one, then clear it.
	user, _, err := svc.Create(ctx, validCreate(), testActor)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(7 * 24 * time.Hour).UTC()
	updated, err := svc.Update(ctx, user.ID, UpdateInput{
		Version:   user.Version,
		ExpiresAt: &later,
	}, testActor)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ExpiresAt == nil || !updated.ExpiresAt.Equal(later) {
		t.Fatalf("expiry not set: %+v", updated.ExpiresAt)
	}

	updated, err = svc.Update(ctx, updated.ID, UpdateInput{
		Version:         updated.Version,
		ClearExpiration: true,
	}, testActor)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ExpiresAt != nil {
		t.Fatalf("expiry not cleared: %v", updated.ExpiresAt)
	}

	// Setting a past expiry is allowed (a correction), but the state
	// builder then excludes the user.
	past := time.Now().Add(-time.Minute).UTC()
	updated, err = svc.Update(ctx, updated.ID, UpdateInput{
		Version:   updated.Version,
		ExpiresAt: &past,
	}, testActor)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := svc.users.ListEngineUsers(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.User.Username == "alice" {
			t.Error("past-expiry user still eligible for the engine state")
		}
	}
}

func TestDisableEnableLifecycle(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	user, _, err := svc.Create(ctx, validCreate(), testActor)
	if err != nil {
		t.Fatal(err)
	}

	disabled, err := svc.Disable(ctx, user.ID, user.Version, testActor)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Status != store.UserDisabled {
		t.Fatalf("status = %q", disabled.Status)
	}
	if rows, _ := svc.users.ListEngineUsers(ctx, time.Now()); len(rows) != 0 {
		t.Error("disabled user still eligible for the engine state")
	}

	enabled, err := svc.Enable(ctx, disabled.ID, disabled.Version, testActor)
	if err != nil {
		t.Fatal(err)
	}
	if enabled.Status != store.UserActive {
		t.Fatalf("status = %q", enabled.Status)
	}

	// Enabling a user whose expiry has passed is refused rather than
	// silently ineffective.
	past := time.Now().Add(-time.Minute).UTC()
	updated, err := svc.Update(ctx, enabled.ID, UpdateInput{
		Version:   enabled.Version,
		ExpiresAt: &past,
	}, testActor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Enable(ctx, updated.ID, updated.Version, testActor); !errors.Is(err, ErrExpired) {
		t.Fatalf("enable of expired user = %v, want ErrExpired", err)
	}
}

func TestRotateCredentialsRevokesOld(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()
	user, firstPassword, err := svc.Create(ctx, validCreate(), testActor)
	if err != nil {
		t.Fatal(err)
	}

	updated, secondPassword, err := svc.RotateCredentials(ctx, user.ID, "", testActor)
	if err != nil {
		t.Fatal(err)
	}
	if secondPassword == firstPassword {
		t.Fatal("rotation returned the same password")
	}
	if updated.Version <= user.Version {
		t.Fatalf("rotation did not bump version: %d -> %d", user.Version, updated.Version)
	}

	// Exactly one active credential remains, and it verifies the new
	// password, not the old one.
	creds := sqlite.NewCredentialRepository(db)
	cred, err := creds.GetActiveForUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := auth.VerifyPassword(secondPassword, cred.APIHash); !ok {
		t.Error("active credential does not verify the new password")
	}
	if ok, _ := auth.VerifyPassword(firstPassword, cred.APIHash); ok {
		t.Error("active credential still verifies the old password")
	}

	var active, revoked int
	rows, err := db.QueryContext(ctx,
		`SELECT status FROM credentials WHERE user_id = ?`, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			t.Fatal(err)
		}
		switch status {
		case store.CredentialActive:
			active++
		case store.CredentialRevoked:
			revoked++
		}
	}
	if active != 1 || revoked != 1 {
		t.Fatalf("credentials after rotation: %d active, %d revoked; want 1/1", active, revoked)
	}
}

func TestDeleteRemovesUserAndCredentials(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()
	user, _, err := svc.Create(ctx, validCreate(), testActor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, user.ID, testActor); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, user.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get after delete = %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM credentials WHERE user_id = ?`, user.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d credentials survived user deletion", n)
	}
}

func TestSweepExpired(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	soon := time.Now().Add(50 * time.Millisecond).UTC()
	expiring, _, err := svc.Create(ctx, CreateInput{
		Username:  "shortlived",
		Protocols: []string{"http"},
		ExpiresAt: &soon,
	}, testActor)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Create(ctx, validCreate(), testActor); err != nil {
		t.Fatal(err)
	}

	time.Sleep(80 * time.Millisecond)
	n, err := svc.SweepExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("sweep expired %d users, want 1", n)
	}
	swept, err := svc.Get(ctx, expiring.ID)
	if err != nil {
		t.Fatal(err)
	}
	if swept.Status != store.UserExpired {
		t.Fatalf("status after sweep = %q", swept.Status)
	}
	// Idempotent: a second sweep changes nothing.
	if n, _ := svc.SweepExpired(ctx); n != 0 {
		t.Fatalf("second sweep expired %d users, want 0", n)
	}
	// The never-expiring user is untouched.
	others, err := svc.List(ctx, store.UserFilter{Status: store.UserActive})
	if err != nil {
		t.Fatal(err)
	}
	if len(others) != 1 || others[0].Username != "alice" {
		t.Fatalf("active users after sweep: %+v", others)
	}
}

func TestAuditTrailContainsNoSecrets(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()
	password := "manual-staple-77x"
	user, _, err := svc.Create(ctx, CreateInput{
		Username:  "bob",
		Password:  password,
		Protocols: []string{"socks5"},
	}, testActor)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RotateCredentials(ctx, user.ID, "", testActor); err != nil {
		t.Fatal(err)
	}

	rows, err := db.QueryContext(ctx, `SELECT actor, action, target, result, detail FROM audit_logs`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var entries int
	for rows.Next() {
		var actor, action, target, result, detail string
		if err := rows.Scan(&actor, &action, &target, &result, &detail); err != nil {
			t.Fatal(err)
		}
		entries++
		combined := actor + action + target + result + detail
		if strings.Contains(combined, password) || strings.Contains(combined, "generated-staple") {
			t.Fatalf("audit entry %q leaks a password: target=%q detail=%q", action, target, detail)
		}
	}
	if entries < 2 {
		t.Fatalf("expected create+rotate audit entries, saw %d", entries)
	}
}

// --- desired-state derivation ---

func TestBuildEngineState(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	now := time.Now()

	monthly := int64(100 * engine.MiB)
	daily := int64(5 * engine.MiB)
	if _, _, err := svc.Create(ctx, CreateInput{
		Username: "alice", Protocols: []string{"http", "socks5"},
		QuotaBytesMonthly: monthly, QuotaBytesDaily: daily,
		DownloadBPS: 20_000_000, UploadBPS: 10_000_000,
	}, testActor); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Create(ctx, CreateInput{
		Username: "bob", Protocols: []string{"http"},
		QuotaBytesDaily: daily,
	}, testActor); err != nil {
		t.Fatal(err)
	}
	// Disabled and expired users exist but must not reach the engine.
	ghost, _, err := svc.Create(ctx, CreateInput{
		Username: "ghost", Protocols: []string{"http"},
	}, testActor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Disable(ctx, ghost.ID, ghost.Version, testActor); err != nil {
		t.Fatal(err)
	}
	past := now.Add(-time.Minute).UTC()
	soon := now.Add(10 * time.Second).UTC()
	old, _, err := svc.Create(ctx, CreateInput{
		Username: "old", Protocols: []string{"http"}, ExpiresAt: &soon,
	}, testActor)
	if err != nil {
		t.Fatal(err)
	}
	// Creating with a past expiry is rejected, so age the user out instead.
	if _, err := svc.Update(ctx, old.ID, UpdateInput{Version: old.Version, ExpiresAt: &past}, testActor); err != nil {
		t.Fatal(err)
	}

	rows, err := svc.users.ListEngineUsers(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	state := BuildEngineState(rows, now)
	if err := state.Validate(); err != nil {
		t.Fatalf("derived state invalid: %v", err)
	}

	if len(state.Users) != 2 {
		t.Fatalf("state has %d users, want 2 (alice, bob): %+v", len(state.Users), state.Users)
	}
	var alice, bob *engine.User
	for i := range state.Users {
		switch state.Users[i].Username {
		case "alice":
			alice = &state.Users[i]
		case "bob":
			bob = &state.Users[i]
		}
	}
	if alice == nil || bob == nil {
		t.Fatal("expected users missing from state")
	}

	// Monthly quota wins when both are set; daily applies when it alone is
	// set; record numbers are DB row ids.
	if alice.Quota == nil || alice.Quota.Period != engine.PeriodMonthly || alice.Quota.LimitBytes != monthly {
		t.Errorf("alice quota = %+v, want monthly %d", alice.Quota, monthly)
	}
	if alice.RecordNumber < 1 {
		t.Errorf("alice record number = %d", alice.RecordNumber)
	}
	if bob.Quota == nil || bob.Quota.Period != engine.PeriodDaily || bob.Quota.LimitBytes != daily {
		t.Errorf("bob quota = %+v, want daily %d", bob.Quota, daily)
	}
	if len(alice.Protocols) != 2 || len(bob.Protocols) != 1 || bob.Protocols[0] != engine.ProtoHTTP {
		t.Errorf("protocols wrong: alice=%v bob=%v", alice.Protocols, bob.Protocols)
	}
	if alice.DownloadBPS != 20_000_000 {
		t.Errorf("alice download = %d", alice.DownloadBPS)
	}

	// The engine hashes came from the active credentials.
	if !strings.HasPrefix(alice.EngineHash, "$3$") {
		t.Errorf("alice engine hash = %q", alice.EngineHash)
	}

	// Determinism: same rows, same state.
	again := BuildEngineState(rows, now)
	if len(again.Users) != len(state.Users) {
		t.Fatal("state derivation not deterministic in length")
	}
}
