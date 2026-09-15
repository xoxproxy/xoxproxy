// Package store defines the persistence contracts of the control plane.
// These interfaces are the seam that keeps SQLite swappable for PostgreSQL
// (ARCHITECTURE.md §7): business code depends only on this package, never
// on a concrete driver.
//
// Conventions for all implementations:
//   - timestamps are time.Time in UTC;
//   - missing rows return ErrNotFound (never sql.ErrNoRows);
//   - byte counters are int64 (never floating point), per GUIDE quotas rule.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a row does not exist. It is the only
// "expected" error; everything else indicates a storage failure.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when an insert violates a uniqueness constraint.
var ErrConflict = errors.New("store: conflict")

// AdminAccount is a dashboard administrator. v1 has exactly one role
// (admin); the model already has an ID so future roles/actors don't force a
// migration of audit references.
type AdminAccount struct {
	ID             int64
	Username       string
	PasswordHash   string
	FailedAttempts int
	LockedUntil    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AdminSession is a server-side session. Only the SHA-256 hash of the
// session token is persisted; the raw token exists in the admin's cookie
// and nowhere else.
type AdminSession struct {
	ID         string
	AccountID  int64
	TokenHash  string
	CSRFToken  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	SourceIP   string
	UserAgent  string
}

// AuditEntry is one privileged-action record. Detail must never contain
// credentials; the audit service enforces size bounds, and handlers are
// reviewed against this rule.
type AuditEntry struct {
	ID        int64
	Timestamp time.Time
	Actor     string
	Action    string
	Target    string
	RequestID string
	SourceIP  string
	UserAgent string
	Result    string // "success" or "failure"
	Detail    string
}

// AuditFilter bounds an audit query. IDs are monotonically increasing, so
// BeforeID gives stable cursor pagination.
type AuditFilter struct {
	Action   string
	BeforeID int64 // 0 = no cursor
	Limit    int   // caller must clamp; repo trusts but verifies
	Offset   int
}

// AdminRepository persists administrator accounts.
type AdminRepository interface {
	CreateAccount(ctx context.Context, a AdminAccount) (AdminAccount, error)
	GetAccountByID(ctx context.Context, id int64) (AdminAccount, error)
	GetAccountByUsername(ctx context.Context, username string) (AdminAccount, error)
	CountAccounts(ctx context.Context) (int64, error)
	UpdatePassword(ctx context.Context, id int64, passwordHash string, now time.Time) error
	RecordLoginFailure(ctx context.Context, id int64, failedAttempts int, lockedUntil *time.Time, now time.Time) error
	ResetFailures(ctx context.Context, id int64, now time.Time) error
}

// SessionRepository persists admin sessions.
type SessionRepository interface {
	CreateSession(ctx context.Context, s AdminSession) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (AdminSession, error)
	TouchSession(ctx context.Context, id string, lastSeen time.Time) error
	DeleteSession(ctx context.Context, id string) error
	DeleteSessionsForAccount(ctx context.Context, accountID int64, exceptSessionID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)
}

// AuditRepository persists and queries audit entries. Entries are
// append-only: no update or delete exists by design (repudiation
// resistance, THREAT-MODEL.md).
type AuditRepository interface {
	Record(ctx context.Context, e AuditEntry) error
	List(ctx context.Context, f AuditFilter) ([]AuditEntry, error)
}

// --- proxy users ---

// Proxy-user lifecycle statuses. "expired" is set by the reconciliation
// sweep; the desired-state builder independently excludes past-expiry
// users so the data plane never serves one even between sweeps.
const (
	UserActive   = "active"
	UserDisabled = "disabled"
	UserExpired  = "expired"
)

// Credential statuses.
const (
	CredentialActive  = "active"
	CredentialRevoked = "revoked"
)

// ProxyUser is a proxy account: the data-plane principal. Password
// verifiers live in Credential; a user always has exactly one active
// credential (rotation swaps it atomically).
type ProxyUser struct {
	ID       int64
	ServerID string // multi-VPS seam; always "local" in v1
	Username string
	Status   string // UserActive | UserDisabled | UserExpired

	// AllowedProtocols is the subset of {"http","socks5"} the account may
	// authenticate against. Never empty for a usable account.
	AllowedProtocols []string

	// DownloadBPS/UploadBPS are instantaneous bandwidth caps (bits/sec);
	// 0 = unlimited. Quotas are accumulated byte allowances; 0 =
	// unlimited. MaxConnections is stored for control-plane enforcement
	// (the engine has no native per-user connection limit — see
	// docs/SPIKE-3PROXY.md §2).
	DownloadBPS       int64
	UploadBPS         int64
	MaxConnections    int64
	QuotaBytesDaily   int64
	QuotaBytesMonthly int64

	ExpiresAt *time.Time // nil = never expires
	Version   int64      // optimistic-lock token; bumped on every mutation

	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastSeenAt *time.Time
}

// Credential is one password generation of a proxy user. EngineHash is the
// data-plane verifier ($3$ BLAKE2b-crypt for 3proxy); APIHash is the
// control-plane verifier (argon2id) for future user-facing verification.
// Neither is ever reversible; the plaintext exists only at create/rotate
// time and is returned to the administrator exactly once.
type Credential struct {
	ID         int64
	UserID     int64
	EngineHash string
	APIHash    string
	Status     string // CredentialActive | CredentialRevoked
	CreatedAt  time.Time
	RotatedAt  *time.Time
}

// UserFilter bounds a user query. IDs are monotonically increasing, so
// BeforeID gives stable cursor pagination.
type UserFilter struct {
	Status   string // "" = all statuses
	Username string // exact match (uniqueness pre-check)
	BeforeID int64  // 0 = no cursor
	Limit    int    // caller must clamp; repo trusts but verifies
	Offset   int
}

// EngineUser pairs an active, unexpired user with the engine hash of its
// active credential: exactly the rows the desired-state builder consumes.
type EngineUser struct {
	User       ProxyUser
	EngineHash string
}

// UserRepository persists proxy users. CreateUser and the credential
// rotation in CredentialRepository are transactional across the users and
// credentials tables — a user is never visible without a credential, and
// a rotation never leaves two active credentials.
type UserRepository interface {
	CreateUser(ctx context.Context, u ProxyUser, initial Credential) (ProxyUser, error)
	GetUserByID(ctx context.Context, id int64) (ProxyUser, error)
	GetUserByUsername(ctx context.Context, username string) (ProxyUser, error)
	ListUsers(ctx context.Context, f UserFilter) ([]ProxyUser, error)
	// UpdateUser applies all mutable fields (protocols, limits, quotas,
	// expiry) under optimistic locking: the row must still carry u.Version,
	// and the returned user has the next version.
	UpdateUser(ctx context.Context, u ProxyUser) (ProxyUser, error)
	DeleteUser(ctx context.Context, id int64) error
	// SetUserStatus transitions lifecycle state (disable/enable/expire)
	// under optimistic locking.
	SetUserStatus(ctx context.Context, id int64, status string, expectedVersion int64, now time.Time) (ProxyUser, error)
	// SweepExpired flips still-active users whose expiry has passed to
	// "expired" and returns how many changed.
	SweepExpired(ctx context.Context, now time.Time) (int64, error)
	// ListEngineUsers returns active, unexpired users with their active
	// engine hashes, ordered by username.
	ListEngineUsers(ctx context.Context, now time.Time) ([]EngineUser, error)
}

// CredentialRepository persists proxy credentials.
type CredentialRepository interface {
	// GetActiveForUser returns the user's active credential.
	GetActiveForUser(ctx context.Context, userID int64) (Credential, error)
	// RotateCredential revokes the active credential, inserts its
	// replacement, and bumps the user's version — all in one transaction.
	// It fails with store.ErrConflict when expectedUserVersion is stale
	// and store.ErrNotFound when the user does not exist.
	RotateCredential(ctx context.Context, userID int64, next Credential, expectedUserVersion int64, now time.Time) (ProxyUser, error)
}

// --- configuration versions ---

// Validation statuses for a configuration version: whether the derived
// engine state passed validation before anything touched the engine.
const (
	ValidationValid   = "valid"   // state validated; rendered and (attempted to be) deployed
	ValidationInvalid = "invalid" // rejected before the engine was touched
	ValidationError   = "error"   // the state could not even be derived
)

// Deployment statuses for a configuration version.
const (
	DeploymentDeployed   = "deployed"    // installed; engine reloaded (or will start with it)
	DeploymentUnchanged  = "unchanged"   // byte-identical to the live config
	DeploymentFailed     = "failed"      // render/deploy error; live config untouched
	DeploymentRolledBack = "rolled_back" // engine died after reload; .prev restored
)

// ConfigurationVersion is one generation of the engine config: who asked
// for it, why, and how the deployment went. Only the checksum is stored —
// the rendered config itself contains credential verifiers and never
// enters the control-plane database or any response.
type ConfigurationVersion struct {
	Revision         int64
	GeneratedAt      time.Time
	GeneratedBy      string // actor name: "admin", "cli", "system" — never free-form input
	Reason           string // fixed vocabulary: "user.create:alice", "startup", "manual", ...
	ValidationStatus string // ValidationValid | ValidationInvalid | ValidationError
	DeploymentStatus string // deployed | unchanged | failed | rolled_back
	Checksum         string // SHA-256 hex of the rendered config; "" when nothing rendered
}

// ConfigurationVersionRepository persists the config-generation history.
// Rows are append-only: a failed or rolled-back deployment is history, not
// something to overwrite — the current live config is always the newest
// row's checksum unless a later deploy replaced it.
type ConfigurationVersionRepository interface {
	// RecordConfigurationVersion appends one row and returns its revision.
	RecordConfigurationVersion(ctx context.Context, v ConfigurationVersion) (int64, error)
	// ListConfigurationVersions returns the newest rows first.
	ListConfigurationVersions(ctx context.Context, limit int) ([]ConfigurationVersion, error)
	// LatestConfigurationVersion returns the newest row, or
	// store.ErrNotFound when nothing has been deployed yet.
	LatestConfigurationVersion(ctx context.Context) (ConfigurationVersion, error)
}

// --- analytics ---

// Protocols a destination stat can be attributed to. Mirrors the engine
// services: the HTTP proxy service carries both plain HTTP and HTTPS
// CONNECT (distinguished by the request text), the SOCKS service is
// SOCKS5.
const (
	StatHTTP  = "http"
	StatHTTPS = "https"
	StatSOCKS = "socks5"
)

// UsagePeriod is one aggregate traffic row of the quota ledger:
// bytes/connections for a user over an hour/day/month window.
type UsagePeriod struct {
	PeriodStart time.Time // window start (UTC)
	Granularity string    // "hour" | "day" | "month"
	BytesIn     int64     // downloads (from target)
	BytesOut    int64     // uploads (to target)
	Connections int64
}

// DestinationStat is one aggregated (host, port, protocol) row for a user
// over a day: the monitoring view. Host is the destination as the client
// requested it — metadata only, never decrypted content.
type DestinationStat struct {
	UserID   int64
	Username string
	Day      string // YYYY-MM-DD, UTC
	Host     string
	Port     int
	Protocol string
	Requests int64
	Blocked  int64
	BytesIn  int64
	BytesOut int64
	LastSeen time.Time
}

// UsageDelta / DestinationDelta are the accumulated increments one flush
// writes. The repository applies them additively (INSERT ... ON CONFLICT
// DO UPDATE ... + delta) so concurrent flushes and restarts converge.
type UsageDelta struct {
	UserID       int64
	Username     string
	Day          string // YYYY-MM-DD, UTC
	Month        string // YYYY-MM, UTC
	BytesIn      int64
	BytesOut     int64
	Connections  int64
	LastSeenUnix int64 // unix millis of newest record seen; 0 = no update
}

type DestinationDelta struct {
	UserID   int64
	Day      string
	Host     string
	Port     int
	Protocol string
	Requests int64
	Blocked  int64
	BytesIn  int64
	BytesOut int64
	LastSeen time.Time
}

// LogCursor records how far the traffic-log tailer has consumed. It is
// updated in the same transaction as the deltas it produced, so a crash
// can neither lose nor double-count flushed traffic.
type LogCursor struct {
	Path   string
	Offset int64
}

// AnalyticsRepository persists and queries traffic accounting. Writes
// happen only through ApplyDeltas — batched, low-frequency, never on the
// proxy path.
type AnalyticsRepository interface {
	// LoadCursor returns the saved traffic-log cursor (zero value when
	// none was saved yet).
	LoadCursor(ctx context.Context) (LogCursor, error)
	// ApplyDeltas atomically adds usage and destination deltas, updates
	// users.last_seen_at for the users involved, and saves the log
	// cursor. A partial apply is impossible.
	ApplyDeltas(ctx context.Context, usage []UsageDelta, destinations []DestinationDelta, cursor LogCursor) error
	// ListUserTraffic returns aggregate usage periods (day granularity)
	// for the user from the given start time, oldest first.
	ListUserTraffic(ctx context.Context, userID int64, since time.Time) ([]UsagePeriod, error)
	// ListGlobalTraffic returns day-granularity usage summed across all
	// users from the given start time, oldest first: the global traffic
	// history of the dashboard overview.
	ListGlobalTraffic(ctx context.Context, since time.Time) ([]UsagePeriod, error)
	// ListUserDestinations returns the user's destination stats for days
	// >= sinceDay (YYYY-MM-DD), ordered by total bytes descending.
	ListUserDestinations(ctx context.Context, userID int64, sinceDay string, limit int) ([]DestinationStat, error)
	// ListTopDestinations returns the global top destinations across all
	// users for days >= sinceDay, ordered by total bytes descending.
	ListTopDestinations(ctx context.Context, sinceDay string, limit int) ([]DestinationStat, error)
	// ListBlockedDestinations returns destinations with blocked requests,
	// ordered by blocked count descending.
	ListBlockedDestinations(ctx context.Context, sinceDay string, limit int) ([]DestinationStat, error)
	// PruneDestinations deletes per-destination stats for days older than
	// the given day and returns how many rows were removed.
	PruneDestinations(ctx context.Context, beforeDay string) (int64, error)
	// ResetUsage zeroes a user's usage ledger for the given day and month
	// periods (the control-plane record of the current quota window).
	// Returns the rows removed.
	ResetUsage(ctx context.Context, userID int64, day, month string) (int64, error)
}
