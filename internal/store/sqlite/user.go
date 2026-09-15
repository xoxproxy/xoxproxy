package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// UserRepository implements store.UserRepository on SQLite.
type UserRepository struct {
	db *DB
}

func NewUserRepository(db *DB) *UserRepository { return &UserRepository{db: db} }

const userColumns = `id, server_id, username, status, allowed_protocols,
	download_limit_bps, upload_limit_bps, max_connections,
	quota_bytes_daily, quota_bytes_monthly, expires_at, version,
	created_at, updated_at, last_seen_at`

func scanUser(row interface{ Scan(...any) error }) (store.ProxyUser, error) {
	var u store.ProxyUser
	var protocols string
	var expiresAt, lastSeen sql.NullString
	var createdAt, updatedAt string
	if err := row.Scan(&u.ID, &u.ServerID, &u.Username, &u.Status, &protocols,
		&u.DownloadBPS, &u.UploadBPS, &u.MaxConnections,
		&u.QuotaBytesDaily, &u.QuotaBytesMonthly, &expiresAt, &u.Version,
		&createdAt, &updatedAt, &lastSeen); err != nil {
		return store.ProxyUser{}, err
	}
	u.AllowedProtocols = splitProtocols(protocols)
	var err error
	if u.ExpiresAt, err = parseNullTime(expiresAt); err != nil {
		return store.ProxyUser{}, err
	}
	if u.LastSeenAt, err = parseNullTime(lastSeen); err != nil {
		return store.ProxyUser{}, err
	}
	if u.CreatedAt, err = parseTime(createdAt); err != nil {
		return store.ProxyUser{}, err
	}
	if u.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return store.ProxyUser{}, err
	}
	return u, nil
}

// joinProtocols/splitProtocols serialize the protocol set. Values are the
// closed vocabulary from the service layer, so a comma join is
// unambiguous.
func joinProtocols(ps []string) string { return strings.Join(ps, ",") }

func splitProtocols(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// CreateUser inserts the user and its initial credential in one
// transaction: a user without a credential can never become visible.
func (r *UserRepository) CreateUser(ctx context.Context, u store.ProxyUser, initial store.Credential) (store.ProxyUser, error) {
	if initial.UserID != 0 && initial.UserID != u.ID {
		return store.ProxyUser{}, fmt.Errorf("sqlite: initial credential belongs to user %d, not %d", initial.UserID, u.ID)
	}
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return store.ProxyUser{}, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO users
			(server_id, username, status, allowed_protocols,
			 download_limit_bps, upload_limit_bps, max_connections,
			 quota_bytes_daily, quota_bytes_monthly, expires_at, version,
			 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		u.ServerID, u.Username, u.Status, joinProtocols(u.AllowedProtocols),
		u.DownloadBPS, u.UploadBPS, u.MaxConnections,
		u.QuotaBytesDaily, u.QuotaBytesMonthly, formatNullTime(u.ExpiresAt),
		formatTime(u.CreatedAt), formatTime(u.UpdatedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return store.ProxyUser{}, fmt.Errorf("%w: username %q already exists", store.ErrConflict, u.Username)
		}
		return store.ProxyUser{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return store.ProxyUser{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO credentials (user_id, engine_hash, api_hash, status, created_at)
		VALUES (?, ?, ?, 'active', ?)`,
		id, initial.EngineHash, initial.APIHash, formatTime(u.CreatedAt)); err != nil {
		return store.ProxyUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.ProxyUser{}, err
	}

	u.ID = id
	u.Version = 1
	return u, nil
}

func (r *UserRepository) GetUserByID(ctx context.Context, id int64) (store.ProxyUser, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ProxyUser{}, store.ErrNotFound
	}
	return u, err
}

func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (store.ProxyUser, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE username = ?`, username)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ProxyUser{}, store.ErrNotFound
	}
	return u, err
}

func (r *UserRepository) ListUsers(ctx context.Context, f store.UserFilter) ([]store.ProxyUser, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	query := `SELECT ` + userColumns + ` FROM users`
	var args []any
	where := ""
	if f.Status != "" {
		where += ` WHERE status = ?`
		args = append(args, f.Status)
	}
	if f.Username != "" {
		if where == "" {
			where = ` WHERE`
		} else {
			where += ` AND`
		}
		where += ` username = ?`
		args = append(args, f.Username)
	}
	if f.BeforeID > 0 {
		if where == "" {
			where = ` WHERE`
		} else {
			where += ` AND`
		}
		where += ` id < ?`
		args = append(args, f.BeforeID)
	}
	query += where + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []store.ProxyUser
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUser applies mutable fields under optimistic locking.
func (r *UserRepository) UpdateUser(ctx context.Context, u store.ProxyUser) (store.ProxyUser, error) {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, `
		UPDATE users SET
			allowed_protocols = ?,
			download_limit_bps = ?,
			upload_limit_bps = ?,
			max_connections = ?,
			quota_bytes_daily = ?,
			quota_bytes_monthly = ?,
			expires_at = ?,
			version = version + 1,
			updated_at = ?
		WHERE id = ? AND version = ?`,
		joinProtocols(u.AllowedProtocols),
		u.DownloadBPS, u.UploadBPS, u.MaxConnections,
		u.QuotaBytesDaily, u.QuotaBytesMonthly, formatNullTime(u.ExpiresAt),
		formatTime(now), u.ID, u.Version)
	if err != nil {
		return store.ProxyUser{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ProxyUser{}, r.versionConflict(ctx, u.ID)
	}
	return r.GetUserByID(ctx, u.ID)
}

func (r *UserRepository) DeleteUser(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *UserRepository) SetUserStatus(ctx context.Context, id int64, status string, expectedVersion int64, now time.Time) (store.ProxyUser, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE users SET status = ?, version = version + 1, updated_at = ?
		WHERE id = ? AND version = ?`,
		status, formatTime(now), id, expectedVersion)
	if err != nil {
		return store.ProxyUser{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ProxyUser{}, r.versionConflict(ctx, id)
	}
	return r.GetUserByID(ctx, id)
}

func (r *UserRepository) SweepExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE users SET status = 'expired', version = version + 1, updated_at = ?
		WHERE status = 'active'
		  AND expires_at IS NOT NULL
		  AND expires_at <= ?`,
		formatTime(now), formatTime(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *UserRepository) ListEngineUsers(ctx context.Context, now time.Time) ([]store.EngineUser, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id, u.server_id, u.username, u.status, u.allowed_protocols,
		       u.download_limit_bps, u.upload_limit_bps, u.max_connections,
		       u.quota_bytes_daily, u.quota_bytes_monthly, u.expires_at, u.version,
		       u.created_at, u.updated_at, u.last_seen_at,
		       c.engine_hash
		FROM users u
		JOIN credentials c ON c.user_id = u.id AND c.status = 'active'
		WHERE u.status = 'active'
		  AND (u.expires_at IS NULL OR u.expires_at > ?)
		ORDER BY u.username`, formatTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.EngineUser
	for rows.Next() {
		// rows.Scan fires once per row, so the extra engine_hash column
		// gets its own scan alongside the shared user fields.
		var u store.ProxyUser
		var protocols string
		var engineHash string
		var expiresAt, lastSeen sql.NullString
		var createdAt, updatedAt string
		if err := rows.Scan(&u.ID, &u.ServerID, &u.Username, &u.Status, &protocols,
			&u.DownloadBPS, &u.UploadBPS, &u.MaxConnections,
			&u.QuotaBytesDaily, &u.QuotaBytesMonthly, &expiresAt, &u.Version,
			&createdAt, &updatedAt, &lastSeen, &engineHash); err != nil {
			return nil, err
		}
		u.AllowedProtocols = splitProtocols(protocols)
		if u.ExpiresAt, err = parseNullTime(expiresAt); err != nil {
			return nil, err
		}
		if u.LastSeenAt, err = parseNullTime(lastSeen); err != nil {
			return nil, err
		}
		if u.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, err
		}
		if u.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, err
		}
		out = append(out, store.EngineUser{User: u, EngineHash: engineHash})
	}
	return out, rows.Err()
}

// versionConflict distinguishes "row missing" from "row changed under us"
// after an optimistic UPDATE matched zero rows.
func (r *UserRepository) versionConflict(ctx context.Context, id int64) error {
	var one int
	err := r.db.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	return store.ErrConflict
}

func formatNullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}
