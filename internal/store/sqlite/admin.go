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

// AdminRepository implements store.AdminRepository on SQLite.
type AdminRepository struct {
	db *DB
}

func NewAdminRepository(db *DB) *AdminRepository { return &AdminRepository{db: db} }

const adminColumns = `id, username, password_hash, failed_attempts, locked_until,
	created_at, updated_at`

func scanAdmin(row interface{ Scan(...any) error }) (store.AdminAccount, error) {
	var a store.AdminAccount
	var lockedUntil sql.NullString
	var createdAt, updatedAt string
	if err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.FailedAttempts,
		&lockedUntil, &createdAt, &updatedAt); err != nil {
		return store.AdminAccount{}, err
	}
	locked, err := parseNullTime(lockedUntil)
	if err != nil {
		return store.AdminAccount{}, err
	}
	a.LockedUntil = locked
	if a.CreatedAt, err = parseTime(createdAt); err != nil {
		return store.AdminAccount{}, err
	}
	if a.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return store.AdminAccount{}, err
	}
	return a, nil
}

func (r *AdminRepository) CreateAccount(ctx context.Context, a store.AdminAccount) (store.AdminAccount, error) {
	now := formatTime(time.Now().UTC())
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	created := formatTime(a.CreatedAt)
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_accounts (username, password_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?)`,
		a.Username, a.PasswordHash, created, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return store.AdminAccount{}, fmt.Errorf("%w: admin %q already exists", store.ErrConflict, a.Username)
		}
		return store.AdminAccount{}, err
	}
	a.ID, err = res.LastInsertId()
	if err != nil {
		return store.AdminAccount{}, err
	}
	a.UpdatedAt = a.CreatedAt
	a.FailedAttempts = 0
	return a, nil
}

func (r *AdminRepository) GetAccountByID(ctx context.Context, id int64) (store.AdminAccount, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+adminColumns+` FROM admin_accounts WHERE id = ?`, id)
	a, err := scanAdmin(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.AdminAccount{}, store.ErrNotFound
	}
	return a, err
}

func (r *AdminRepository) GetAccountByUsername(ctx context.Context, username string) (store.AdminAccount, error) {
	// Usernames are matched case-insensitively at the schema level
	// (COLLATE NOCASE); the parameter must be plain, not folded, to use
	// the index.
	row := r.db.QueryRowContext(ctx,
		`SELECT `+adminColumns+` FROM admin_accounts WHERE username = ?`, username)
	a, err := scanAdmin(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.AdminAccount{}, store.ErrNotFound
	}
	return a, err
}

func (r *AdminRepository) CountAccounts(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM admin_accounts`).Scan(&n)
	return n, err
}

func (r *AdminRepository) UpdatePassword(ctx context.Context, id int64, passwordHash string, now time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE admin_accounts
		SET password_hash = ?, updated_at = ?, failed_attempts = 0, locked_until = NULL
		WHERE id = ?`,
		passwordHash, formatTime(now), id)
	if err != nil {
		return err
	}
	return assertUpdated(res)
}

func (r *AdminRepository) RecordLoginFailure(ctx context.Context, id int64, failedAttempts int, lockedUntil *time.Time, now time.Time) error {
	var locked any
	if lockedUntil != nil {
		locked = formatTime(*lockedUntil)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE admin_accounts
		SET failed_attempts = ?, locked_until = ?, updated_at = ?
		WHERE id = ?`,
		failedAttempts, locked, formatTime(now), id)
	if err != nil {
		return err
	}
	return assertUpdated(res)
}

func (r *AdminRepository) ResetFailures(ctx context.Context, id int64, now time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE admin_accounts
		SET failed_attempts = 0, locked_until = NULL, updated_at = ?
		WHERE id = ?`, formatTime(now), id)
	if err != nil {
		return err
	}
	return assertUpdated(res)
}

func assertUpdated(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
