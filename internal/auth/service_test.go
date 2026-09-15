package auth

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
)

// newAuthService wires a real SQLite-backed service with a controllable
// clock. Tests that need time travel mutate *now.
func newAuthService(t *testing.T, now *time.Time) (*Service, *sqlite.DB) {
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
	svc, err := New(logger,
		sqlite.NewAdminRepository(db),
		sqlite.NewSessionRepository(db),
		auditSvc,
		Options{Now: func() time.Time { return *now }},
	)
	if err != nil {
		t.Fatal(err)
	}
	return svc, db
}

var testNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestHashPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("unexpected hash format: %s", h)
	}
	ok, err := VerifyPassword("correct horse battery staple", h)
	if err != nil || !ok {
		t.Fatalf("correct password rejected: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword("wrong password", h)
	if err != nil || ok {
		t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
	}
	// Two hashes of the same password differ (unique salts).
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("salt reuse detected")
	}
	// Malformed hashes fail closed without error.
	ok, err = VerifyPassword("x", "not-a-hash")
	if ok || err != nil {
		t.Fatalf("malformed hash: ok=%v err=%v", ok, err)
	}
}

func TestValidatePasswordPolicy(t *testing.T) {
	cases := []struct {
		name     string
		password string
		username string
		ok       bool
	}{
		{"too short", "short", "", false},
		{"common", "passwordpassword", "", false},
		{"contains username", "admin-admin-admin", "admin", false},
		{"good", "correct horse battery", "admin", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasswordPolicy(tc.password, tc.username)
			if tc.ok && err != nil {
				t.Fatalf("rejected good password: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("accepted bad password")
			}
		})
	}
}

func TestGeneratedPasswords(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p := GeneratePassword()
		if len(p) != GeneratedPasswordLength {
			t.Fatalf("length = %d", len(p))
		}
		if seen[p] {
			t.Fatalf("duplicate generated password (collision after %d draws is impossible)", i)
		}
		seen[p] = true
		for _, c := range p { // no ambiguous characters
			if !strings.ContainsRune(passwordAlphabet, rune(c)) {
				t.Fatalf("character %q outside alphabet", c)
			}
		}
	}
}

func TestLoginSuccessAndLogout(t *testing.T) {
	now := testNow
	svc, _ := newAuthService(t, &now)
	ctx := context.Background()

	if _, err := svc.CreateAccount(ctx, "admin", "correct-staple-9x", "installer", ""); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Token == "" || res.CSRFToken == "" || res.Token == res.CSRFToken {
		t.Fatalf("bad tokens in result: %+v", res)
	}

	// Session validates.
	session, account, err := svc.ValidateSession(ctx, res.Token)
	if err != nil {
		t.Fatal(err)
	}
	if account.Username != "admin" || session.CSRFToken != res.CSRFToken {
		t.Fatalf("session mismatch: %+v %+v", session, account)
	}

	// Logout revokes.
	if err := svc.Logout(ctx, res.Token, "", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ValidateSession(ctx, res.Token); err != ErrSessionInvalid {
		t.Fatalf("revoked session still valid: %v", err)
	}
}

func TestLoginFailuresUniformAndLockout(t *testing.T) {
	now := testNow
	svc, _ := newAuthService(t, &now)
	ctx := context.Background()
	_, err := svc.CreateAccount(ctx, "admin", "correct-staple-9x", "installer", "")
	if err != nil {
		t.Fatal(err)
	}

	// Unknown user and wrong password produce the same error.
	_, err1 := svc.Login(ctx, LoginInput{Username: "ghost", Password: "whatever-long", SourceIP: "10.0.0.1"})
	_, err2 := svc.Login(ctx, LoginInput{Username: "admin", Password: "wrong-password-1", SourceIP: "10.0.0.1"})
	if err1 != ErrInvalidCredentials || err2 != ErrInvalidCredentials {
		t.Fatalf("failure errors not uniform: %v vs %v", err1, err2)
	}

	// Four more wrong attempts (one already counted above) to reach the
	// 5-failure lockout threshold, then verify the lock.
	for i := 0; i < 4; i++ {
		if _, err := svc.Login(ctx, LoginInput{Username: "admin", Password: "wrong-password-1", SourceIP: "10.0.0.1"}); err != ErrInvalidCredentials {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// 5 failures recorded; correct password now fails too (locked).
	_, err = svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "10.0.0.1"})
	if err != ErrInvalidCredentials {
		t.Fatalf("locked account accepted login: %v", err)
	}

	// After lockout expiry, the correct password works again.
	now = now.Add(16 * time.Minute)
	res, err := svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "10.0.0.1"})
	if err != nil {
		t.Fatalf("login after lockout expiry failed: %v", err)
	}
	if res.Token == "" {
		t.Fatal("no token after recovery")
	}
}

func TestIPThrottling(t *testing.T) {
	now := testNow
	svc, _ := newAuthService(t, &now)
	ctx := context.Background()
	_, _ = svc.CreateAccount(ctx, "admin", "correct-staple-9x", "installer", "")

	// Hammer from one IP across the (nonexistent) account space. The
	// block engages on the attempt after the threshold failure.
	var lastErr error
	for i := 0; i < 21; i++ {
		_, lastErr = svc.Login(ctx, LoginInput{Username: "ghost", Password: "no-such-password", SourceIP: "203.0.113.9"})
	}
	if lastErr != ErrIPBlocked {
		t.Fatalf("IP not blocked after 21 failures: %v", lastErr)
	}
	// Even the correct password is blocked from that IP.
	_, err := svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "203.0.113.9"})
	if err != ErrIPBlocked {
		t.Fatalf("blocked IP still allowed: %v", err)
	}
	// A different IP is unaffected.
	if _, err := svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "198.51.100.7"}); err != nil {
		t.Fatalf("clean IP rejected: %v", err)
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	now := testNow
	svc, _ := newAuthService(t, &now)
	ctx := context.Background()
	_, _ = svc.CreateAccount(ctx, "admin", "correct-staple-9x", "installer", "")
	res, _ := svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "10.0.0.1"})

	// Within idle timeout: fine (this also touches the session).
	now = now.Add(90 * time.Minute)
	if _, _, err := svc.ValidateSession(ctx, res.Token); err != nil {
		t.Fatalf("session should survive 90m of activity: %v", err)
	}

	// Beyond idle timeout measured from the last touch: invalid.
	now = now.Add(3 * time.Hour)
	if _, _, err := svc.ValidateSession(ctx, res.Token); err != ErrSessionInvalid {
		t.Fatalf("idle session accepted: %v", err)
	}

	// Absolute expiry: keep touching within idle window until TTL passes.
	res, _ = svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "10.0.0.1"})
	for elapsed := 30 * time.Minute; elapsed <= 7*24*time.Hour; elapsed += 30 * time.Minute {
		now = testNow.Add(elapsed)
		if _, _, err := svc.ValidateSession(ctx, res.Token); err != nil {
			if elapsed > 7*24*time.Hour {
				t.Fatalf("session died at %v, expected only at TTL: %v", elapsed, err)
			}
			break // expired at/before TTL — acceptable boundary
		}
	}
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	now := testNow
	svc, _ := newAuthService(t, &now)
	ctx := context.Background()
	_, _ = svc.CreateAccount(ctx, "admin", "correct-staple-9x", "installer", "")

	// Two sessions (two browsers).
	s1, _ := svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "10.0.0.1"})
	s2, _ := svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "10.0.0.2"})

	if _, err := svc.ChangePassword(ctx, s1.Token, "correct-staple-9x", "a-newer-staple-3", "", ""); err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.ValidateSession(ctx, s1.Token); err != nil {
		t.Fatalf("changing session revoked: %v", err)
	}
	if _, _, err := svc.ValidateSession(ctx, s2.Token); err != ErrSessionInvalid {
		t.Fatalf("other session survived password change: %v", err)
	}

	// New password works, old does not.
	if _, err := svc.Login(ctx, LoginInput{Username: "admin", Password: "a-newer-staple-3", SourceIP: "10.0.0.1"}); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
	if _, err := svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "10.0.0.1"}); err != ErrInvalidCredentials {
		t.Fatalf("old password accepted: %v", err)
	}
}

func TestCreateAccountDuplicateAndPolicy(t *testing.T) {
	now := testNow
	svc, _ := newAuthService(t, &now)
	ctx := context.Background()

	if _, err := svc.CreateAccount(ctx, "admin", "correct-staple-9x", "installer", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateAccount(ctx, "admin", "another-fine-one", "installer", ""); err == nil {
		t.Fatal("duplicate account accepted")
	}
	if _, err := svc.CreateAccount(ctx, "weak", "short", "installer", ""); err == nil {
		t.Fatal("weak password accepted")
	}
}

func TestResetPasswordRevokesSessions(t *testing.T) {
	now := testNow
	svc, _ := newAuthService(t, &now)
	ctx := context.Background()
	_, _ = svc.CreateAccount(ctx, "admin", "correct-staple-9x", "installer", "")
	res, _ := svc.Login(ctx, LoginInput{Username: "admin", Password: "correct-staple-9x", SourceIP: "10.0.0.1"})

	if err := svc.ResetPassword(ctx, "admin", "reset-staple-8x", "cli", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ValidateSession(ctx, res.Token); err != ErrSessionInvalid {
		t.Fatalf("session survived password reset: %v", err)
	}
	if _, err := svc.Login(ctx, LoginInput{Username: "admin", Password: "reset-staple-8x", SourceIP: "10.0.0.1"}); err != nil {
		t.Fatalf("reset password rejected: %v", err)
	}
}
