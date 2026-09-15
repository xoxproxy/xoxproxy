package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// Sentinel errors. The API layer maps ErrInvalidCredentials and
// ErrIPBlocked to identical-looking 401/429 responses so callers learn
// nothing about account existence.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrIPBlocked          = errors.New("too many attempts from this address")
	ErrSessionInvalid     = errors.New("session invalid or expired")
	ErrUsernameTaken      = errors.New("username already exists")
)

// Options tunes the service. Zero values fall back to the defaults below;
// tests inject Now to control time.
type Options struct {
	Now func() time.Time

	SessionTTL    time.Duration // absolute session lifetime
	IdleTimeout   time.Duration // inactivity timeout
	MaxFailures   int           // per-account failures before lockout
	Lockout       time.Duration // per-account lockout duration
	IPMaxFailures int           // per-IP failures across all accounts
	IPWindow      time.Duration // sliding failure window per IP
	IPLockout     time.Duration // per-IP block duration
}

func (o *Options) applyDefaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.SessionTTL == 0 {
		o.SessionTTL = 7 * 24 * time.Hour
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 2 * time.Hour
	}
	if o.MaxFailures == 0 {
		o.MaxFailures = 5
	}
	if o.Lockout == 0 {
		o.Lockout = 15 * time.Minute
	}
	if o.IPMaxFailures == 0 {
		o.IPMaxFailures = 20
	}
	if o.IPWindow == 0 {
		o.IPWindow = 15 * time.Minute
	}
	if o.IPLockout == 0 {
		o.IPLockout = 15 * time.Minute
	}
}

// AuditRecorder is the audit sink. Declared here (not *audit.Service) to
// keep the auth package independent of the audit implementation.
type AuditRecorder interface {
	Record(ctx context.Context, e store.AuditEntry) error
}

// Service implements admin authentication and session management.
type Service struct {
	admins   store.AdminRepository
	sessions store.SessionRepository
	audit    AuditRecorder
	logger   *slog.Logger
	opts     Options

	// dummyHash exists to equalize timing between "no such user" and
	// "wrong password" responses (username enumeration via latency).
	dummyHash string

	ips *ipLimiter
}

func New(logger *slog.Logger, admins store.AdminRepository, sessions store.SessionRepository, auditSink AuditRecorder, opts Options) (*Service, error) {
	opts.applyDefaults()
	// Precompute the timing-equalization hash; failure is unrecoverable.
	dummy, err := HashPassword("timing-equalization-dummy")
	if err != nil {
		return nil, err
	}
	return &Service{
		admins:    admins,
		sessions:  sessions,
		audit:     auditSink,
		logger:    logger,
		opts:      opts,
		dummyHash: dummy,
		ips:       newIPLimiter(opts),
	}, nil
}

// LoginInput carries an authentication attempt plus request context for
// the audit trail.
type LoginInput struct {
	Username  string
	Password  string
	SourceIP  string
	UserAgent string
	RequestID string
}

// LoginResult is a successful authentication. Token is the raw session
// token (the only time it exists outside the admin's cookie); CSRFToken is
// the per-session token the SPA must echo as X-CSRF-Token on mutations.
type LoginResult struct {
	Token     string
	CSRFToken string
	Account   store.AdminAccount
	ExpiresAt time.Time
}

// Login authenticates an administrator and creates a session. All failure
// paths return ErrInvalidCredentials or ErrIPBlocked — never account
// existence or lock state.
func (s *Service) Login(ctx context.Context, in LoginInput) (LoginResult, error) {
	now := s.opts.Now().UTC()

	fail := func(reason string, accountID int64, account store.AdminAccount, haveAccount bool) (LoginResult, error) {
		s.ips.recordFailure(in.SourceIP, now)
		if haveAccount {
			attempts := account.FailedAttempts + 1
			var lockedUntil *time.Time
			if attempts >= s.opts.MaxFailures {
				t := now.Add(s.opts.Lockout)
				lockedUntil = &t
			}
			if err := s.admins.RecordLoginFailure(ctx, accountID, attempts, lockedUntil, now); err != nil {
				s.logger.Error("failed to record login failure", slog.String("error", err.Error()))
			}
		}
		s.auditLogin(ctx, in, "failure", reason)
		return LoginResult{}, ErrInvalidCredentials
	}

	if blocked, _ := s.ips.blocked(in.SourceIP, now); blocked {
		s.auditLogin(ctx, in, "failure", "ip blocked")
		return LoginResult{}, ErrIPBlocked
	}

	account, err := s.admins.GetAccountByUsername(ctx, in.Username)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Burn the same argon2 work as a real verification so response
		// timing does not reveal whether the account exists.
		_, _ = VerifyPassword(in.Password, s.dummyHash)
		return fail("unknown account", 0, store.AdminAccount{}, false)
	case err != nil:
		return LoginResult{}, fmt.Errorf("auth: lookup: %w", err)
	}

	if account.LockedUntil != nil {
		if account.LockedUntil.After(now) {
			return fail("account locked", account.ID, account, true)
		}
		// Expired lockout: clear it before evaluating the attempt.
		if err := s.admins.ResetFailures(ctx, account.ID, now); err != nil {
			return LoginResult{}, fmt.Errorf("auth: reset lockout: %w", err)
		}
		account.FailedAttempts = 0
		account.LockedUntil = nil
	}

	ok, err := VerifyPassword(in.Password, account.PasswordHash)
	if err != nil || !ok {
		return fail("bad password", account.ID, account, true)
	}

	// Success: reset counters, mint the session.
	s.ips.recordSuccess(in.SourceIP)
	if err := s.admins.ResetFailures(ctx, account.ID, now); err != nil {
		return LoginResult{}, fmt.Errorf("auth: reset failures: %w", err)
	}
	token, err := NewToken()
	if err != nil {
		return LoginResult{}, err
	}
	csrf, err := NewToken()
	if err != nil {
		return LoginResult{}, err
	}
	session := store.AdminSession{
		ID:         NewSessionID(),
		AccountID:  account.ID,
		TokenHash:  HashToken(token),
		CSRFToken:  csrf,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.opts.SessionTTL),
		LastSeenAt: now,
		SourceIP:   in.SourceIP,
		UserAgent:  in.UserAgent,
	}
	if err := s.sessions.CreateSession(ctx, session); err != nil {
		return LoginResult{}, fmt.Errorf("auth: create session: %w", err)
	}

	// Opportunistic cleanup of expired sessions (bounded work, one query).
	if n, err := s.sessions.DeleteExpiredSessions(ctx, now); err == nil && n > 0 {
		s.logger.Info("pruned expired sessions", slog.Int64("count", n))
	}

	s.auditLogin(ctx, in, "success", "")
	return LoginResult{
		Token:     token,
		CSRFToken: csrf,
		Account:   account,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *Service) auditLogin(ctx context.Context, in LoginInput, result, detail string) {
	if s.audit == nil {
		return
	}
	entry := store.AuditEntry{
		Timestamp: s.opts.Now().UTC(),
		Actor:     in.Username,
		Action:    "admin.login",
		Target:    in.Username,
		RequestID: in.RequestID,
		SourceIP:  in.SourceIP,
		UserAgent: in.UserAgent,
		Result:    result,
		Detail:    detail,
	}
	if err := s.audit.Record(ctx, entry); err != nil {
		// Already logged by the audit service; authentication itself
		// must not fail because the audit write did.
		_ = err
	}
}

// ValidateSession resolves a raw session token to its session and account,
// enforcing both the absolute expiry and the idle timeout. A token that
// fails any check is deleted when possible.
func (s *Service) ValidateSession(ctx context.Context, token string) (store.AdminSession, store.AdminAccount, error) {
	now := s.opts.Now().UTC()
	session, err := s.sessions.GetSessionByTokenHash(ctx, HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return store.AdminSession{}, store.AdminAccount{}, ErrSessionInvalid
	}
	if err != nil {
		return store.AdminSession{}, store.AdminAccount{}, fmt.Errorf("auth: session lookup: %w", err)
	}
	if session.ExpiresAt.Before(now) || session.LastSeenAt.Add(s.opts.IdleTimeout).Before(now) {
		_ = s.sessions.DeleteSession(ctx, session.ID)
		return store.AdminSession{}, store.AdminAccount{}, ErrSessionInvalid
	}
	account, err := s.admins.GetAccountByID(ctx, session.AccountID)
	if errors.Is(err, store.ErrNotFound) {
		_ = s.sessions.DeleteSession(ctx, session.ID)
		return store.AdminSession{}, store.AdminAccount{}, ErrSessionInvalid
	}
	if err != nil {
		return store.AdminSession{}, store.AdminAccount{}, fmt.Errorf("auth: account lookup: %w", err)
	}
	if err := s.sessions.TouchSession(ctx, session.ID, now); err != nil {
		// A failed touch must not invalidate an otherwise valid request.
		s.logger.Warn("session touch failed", slog.String("error", err.Error()))
	}
	return session, account, nil
}

// Logout revokes the session bound to token.
func (s *Service) Logout(ctx context.Context, token, requestID, sourceIP string) error {
	session, err := s.sessions.GetSessionByTokenHash(ctx, HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil // idempotent
	}
	if err != nil {
		return fmt.Errorf("auth: logout lookup: %w", err)
	}
	if err := s.sessions.DeleteSession(ctx, session.ID); err != nil {
		return fmt.Errorf("auth: logout: %w", err)
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, store.AuditEntry{
			Actor: "admin", Action: "admin.logout", RequestID: requestID,
			SourceIP: sourceIP, Result: "success",
		})
	}
	return nil
}

// ChangePassword verifies the current password, applies policy to the new
// one, and revokes every other session of the account.
func (s *Service) ChangePassword(ctx context.Context, token, currentPassword, newPassword, requestID, sourceIP string) (store.AdminSession, error) {
	session, account, err := s.ValidateSession(ctx, token)
	if err != nil {
		return store.AdminSession{}, err
	}
	ok, err := VerifyPassword(currentPassword, account.PasswordHash)
	if err != nil || !ok {
		if s.audit != nil {
			_ = s.audit.Record(ctx, store.AuditEntry{
				Actor: account.Username, Action: "admin.password_change",
				RequestID: requestID, SourceIP: sourceIP, Result: "failure",
				Detail: "current password incorrect",
			})
		}
		return store.AdminSession{}, ErrInvalidCredentials
	}
	if err := ValidatePasswordPolicy(newPassword, account.Username); err != nil {
		return store.AdminSession{}, err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return store.AdminSession{}, err
	}
	now := s.opts.Now().UTC()
	if err := s.admins.UpdatePassword(ctx, account.ID, hash, now); err != nil {
		return store.AdminSession{}, fmt.Errorf("auth: update password: %w", err)
	}
	if err := s.sessions.DeleteSessionsForAccount(ctx, account.ID, session.ID); err != nil {
		return store.AdminSession{}, fmt.Errorf("auth: revoke sessions: %w", err)
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, store.AuditEntry{
			Actor: account.Username, Action: "admin.password_change",
			RequestID: requestID, SourceIP: sourceIP, Result: "success",
			Detail: "other sessions revoked",
		})
	}
	return session, nil
}

// CreateAccount creates the first or an additional administrator.
func (s *Service) CreateAccount(ctx context.Context, username, password, actor, requestID string) (store.AdminAccount, error) {
	if err := ValidatePasswordPolicy(password, username); err != nil {
		return store.AdminAccount{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return store.AdminAccount{}, err
	}
	account, err := s.admins.CreateAccount(ctx, store.AdminAccount{
		Username: username, PasswordHash: hash,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.AdminAccount{}, fmt.Errorf("%w: %w", ErrUsernameTaken, err)
		}
		return store.AdminAccount{}, fmt.Errorf("auth: create account: %w", err)
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, store.AuditEntry{
			Actor: actor, Action: "admin.account_created", Target: username,
			RequestID: requestID, Result: "success",
		})
	}
	return account, nil
}

// ResetPassword replaces an account's password and revokes all its
// sessions. Used by the CLI (local, authenticated by machine access).
func (s *Service) ResetPassword(ctx context.Context, username, newPassword, actor, requestID string) error {
	account, err := s.admins.GetAccountByUsername(ctx, username)
	if err != nil {
		return err
	}
	if err := ValidatePasswordPolicy(newPassword, username); err != nil {
		return err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.admins.UpdatePassword(ctx, account.ID, hash, s.opts.Now().UTC()); err != nil {
		return err
	}
	if err := s.sessions.DeleteSessionsForAccount(ctx, account.ID, ""); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, store.AuditEntry{
			Actor: actor, Action: "admin.password_reset", Target: username,
			RequestID: requestID, Result: "success", Detail: "all sessions revoked",
		})
	}
	return nil
}

// --- tokens ---

// NewToken returns a 256-bit URL-safe random token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewSessionID returns a random session row identifier.
func NewSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("auth: entropy source unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// HashToken is the storage form of session tokens: only the hash is
// persisted, so a stolen database cannot be replayed as sessions.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- per-IP failure limiter ---

type ipLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipEntry
	opts    Options
}

type ipEntry struct {
	failures     []time.Time
	blockedUntil time.Time
}

func newIPLimiter(opts Options) *ipLimiter {
	return &ipLimiter{entries: map[string]*ipEntry{}, opts: opts}
}

func (l *ipLimiter) blocked(ip string, now time.Time) (bool, time.Duration) {
	if ip == "" {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		return false, 0
	}
	if e.blockedUntil.After(now) {
		return true, e.blockedUntil.Sub(now)
	}
	return false, 0
}

func (l *ipLimiter) recordFailure(ip string, now time.Time) {
	if ip == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)

	e := l.entries[ip]
	if e == nil {
		e = &ipEntry{}
		l.entries[ip] = e
	}
	// Keep only failures inside the sliding window.
	kept := e.failures[:0]
	for _, f := range e.failures {
		if now.Sub(f) <= l.opts.IPWindow {
			kept = append(kept, f)
		}
	}
	kept = append(kept, now)
	e.failures = kept
	if len(e.failures) >= l.opts.IPMaxFailures {
		e.blockedUntil = now.Add(l.opts.IPLockout)
		e.failures = nil
	}
}

func (l *ipLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// prune drops expired entries when the map grows past a hard bound; it is
// called with the lock held. The bound keeps memory predictable even under
// distributed scanning (entries whose lockout has lapsed go first).
const maxTrackedIPs = 8192

func (l *ipLimiter) prune(now time.Time) {
	if len(l.entries) < maxTrackedIPs {
		return
	}
	for ip, e := range l.entries {
		if !e.blockedUntil.After(now) && (len(e.failures) == 0 ||
			now.Sub(e.failures[len(e.failures)-1]) > l.opts.IPWindow) {
			delete(l.entries, ip)
		}
	}
}
