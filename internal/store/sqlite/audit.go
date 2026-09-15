package sqlite

import (
	"context"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// AuditRepository implements store.AuditRepository on SQLite. Entries are
// append-only; there is deliberately no update or delete path.
type AuditRepository struct {
	db *DB
}

func NewAuditRepository(db *DB) *AuditRepository { return &AuditRepository{db: db} }

// maxAuditDetail bounds the detail field so a buggy caller cannot bloat
// the audit table with unbounded data.
const maxAuditDetail = 2000

func (r *AuditRepository) Record(ctx context.Context, e store.AuditEntry) error {
	if len(e.Detail) > maxAuditDetail {
		e.Detail = e.Detail[:maxAuditDetail]
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_logs
			(ts, actor, action, target, request_id, source_ip, user_agent, result, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		formatTime(e.Timestamp), e.Actor, e.Action, e.Target, e.RequestID,
		e.SourceIP, e.UserAgent, e.Result, e.Detail)
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

func (r *AuditRepository) List(ctx context.Context, f store.AuditFilter) ([]store.AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	query := `
		SELECT id, ts, actor, action, target, request_id, source_ip, user_agent, result, detail
		FROM audit_logs`
	var args []any
	where := ""
	if f.Action != "" {
		where += ` WHERE action = ?`
		args = append(args, f.Action)
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

	var entries []store.AuditEntry
	for rows.Next() {
		var e store.AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target,
			&e.RequestID, &e.SourceIP, &e.UserAgent, &e.Result, &e.Detail); err != nil {
			return nil, err
		}
		parsed, err := parseTime(ts)
		if err != nil {
			return nil, err
		}
		e.Timestamp = parsed
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
