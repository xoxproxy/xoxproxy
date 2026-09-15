package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// isNoRows reports the driver's no-rows condition without leaking
// database/sql types into signatures.
func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// CredentialRepository implements store.CredentialRepository on SQLite.
type CredentialRepository struct {
	db *DB
}

func NewCredentialRepository(db *DB) *CredentialRepository { return &CredentialRepository{db: db} }

func (r *CredentialRepository) GetActiveForUser(ctx context.Context, userID int64) (store.Credential, error) {
	var c store.Credential
	var createdAt string
	var rotatedAt *string
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, engine_hash, api_hash, status, created_at, rotated_at
		FROM credentials
		WHERE user_id = ? AND status = 'active'
		ORDER BY id DESC
		LIMIT 1`, userID).
		Scan(&c.ID, &c.UserID, &c.EngineHash, &c.APIHash, &c.Status, &createdAt, &rotatedAt)
	if err != nil {
		if isNoRows(err) {
			return store.Credential{}, store.ErrNotFound
		}
		return store.Credential{}, err
	}
	if c.CreatedAt, err = parseTime(createdAt); err != nil {
		return store.Credential{}, err
	}
	if rotatedAt != nil {
		t, err := parseTime(*rotatedAt)
		if err != nil {
			return store.Credential{}, err
		}
		c.RotatedAt = &t
	}
	return c, nil
}

// RotateCredential atomically revokes the active credential, inserts the
// replacement, and bumps the user's optimistic-lock version. The insert
// happens before the revoke check would matter — a failure at any point
// rolls back both, so a user never ends up with zero or two active
// credentials.
func (r *CredentialRepository) RotateCredential(ctx context.Context, userID int64, next store.Credential, expectedUserVersion int64, now time.Time) (store.ProxyUser, error) {
	if next.UserID != 0 && next.UserID != userID {
		return store.ProxyUser{}, fmt.Errorf("sqlite: replacement credential belongs to user %d, not %d", next.UserID, userID)
	}
	if next.CreatedAt.IsZero() {
		next.CreatedAt = now
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return store.ProxyUser{}, err
	}
	defer tx.Rollback()

	// Bump the user version first: a stale expectedUserVersion aborts the
	// whole rotation before any credential row is touched.
	res, err := tx.ExecContext(ctx, `
		UPDATE users SET version = version + 1, updated_at = ?
		WHERE id = ? AND version = ?`,
		formatTime(now), userID, expectedUserVersion)
	if err != nil {
		return store.ProxyUser{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Distinguish a missing user from a version race inside the tx.
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, userID).Scan(&one)
		if isNoRows(err) {
			return store.ProxyUser{}, store.ErrNotFound
		}
		if err != nil {
			return store.ProxyUser{}, err
		}
		return store.ProxyUser{}, store.ErrConflict
	}

	revoked := formatTime(now)
	if _, err := tx.ExecContext(ctx, `
		UPDATE credentials SET status = 'revoked', rotated_at = ?
		WHERE user_id = ? AND status = 'active'`, revoked, userID); err != nil {
		return store.ProxyUser{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO credentials (user_id, engine_hash, api_hash, status, created_at)
		VALUES (?, ?, ?, 'active', ?)`,
		userID, next.EngineHash, next.APIHash, formatTime(next.CreatedAt)); err != nil {
		return store.ProxyUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.ProxyUser{}, err
	}

	users := NewUserRepository(r.db)
	return users.GetUserByID(ctx, userID)
}
