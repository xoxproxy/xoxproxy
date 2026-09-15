package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// SessionRepository implements store.SessionRepository on SQLite.
type SessionRepository struct {
	db *DB
}

func NewSessionRepository(db *DB) *SessionRepository { return &SessionRepository{db: db} }

const sessionColumns = `id, account_id, token_hash, csrf_token,
	created_at, expires_at, last_seen_at, source_ip, user_agent`

func scanSession(row interface{ Scan(...any) error }) (store.AdminSession, error) {
	var s store.AdminSession
	var createdAt, expiresAt, lastSeenAt string
	if err := row.Scan(&s.ID, &s.AccountID, &s.TokenHash, &s.CSRFToken,
		&createdAt, &expiresAt, &lastSeenAt, &s.SourceIP, &s.UserAgent); err != nil {
		return store.AdminSession{}, err
	}
	var err error
	if s.CreatedAt, err = parseTime(createdAt); err != nil {
		return store.AdminSession{}, err
	}
	if s.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return store.AdminSession{}, err
	}
	if s.LastSeenAt, err = parseTime(lastSeenAt); err != nil {
		return store.AdminSession{}, err
	}
	return s, nil
}

func (r *SessionRepository) CreateSession(ctx context.Context, s store.AdminSession) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_sessions
			(id, account_id, token_hash, csrf_token, created_at, expires_at,
			 last_seen_at, source_ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.AccountID, s.TokenHash, s.CSRFToken,
		formatTime(s.CreatedAt), formatTime(s.ExpiresAt), formatTime(s.LastSeenAt),
		s.SourceIP, s.UserAgent)
	return err
}

func (r *SessionRepository) GetSessionByTokenHash(ctx context.Context, tokenHash string) (store.AdminSession, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM admin_sessions WHERE token_hash = ?`, tokenHash)
	s, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.AdminSession{}, store.ErrNotFound
	}
	return s, err
}

func (r *SessionRepository) TouchSession(ctx context.Context, id string, lastSeen time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?`,
		formatTime(lastSeen), id)
	return err
}

func (r *SessionRepository) DeleteSession(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM admin_sessions WHERE id = ?`, id)
	return err
}

// DeleteSessionsForAccount removes every session of an account except the
// given one. Used after password changes: the changing session survives,
// all others (possibly stolen) die immediately.
func (r *SessionRepository) DeleteSessionsForAccount(ctx context.Context, accountID int64, exceptSessionID string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM admin_sessions
		WHERE account_id = ? AND id <> ?`, accountID, exceptSessionID)
	return err
}

func (r *SessionRepository) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM admin_sessions WHERE expires_at < ?`, formatTime(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
