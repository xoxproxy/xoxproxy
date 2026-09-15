package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// cursorKey is the settings-table key holding the traffic-log cursor.
const cursorKey = "analytics.log_cursor"

// AnalyticsRepository implements store.AnalyticsRepository on SQLite.
// All writes go through ApplyDeltas: one transaction per flush batch,
// never per request.
type AnalyticsRepository struct {
	db *DB
}

func NewAnalyticsRepository(db *DB) *AnalyticsRepository {
	return &AnalyticsRepository{db: db}
}

func (r *AnalyticsRepository) LoadCursor(ctx context.Context) (store.LogCursor, error) {
	var raw string
	err := r.db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE key = ?`, cursorKey).Scan(&raw)
	if err != nil {
		if isNoRows(err) {
			return store.LogCursor{}, nil
		}
		return store.LogCursor{}, err
	}
	var c store.LogCursor
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		// A corrupt cursor is history's problem, not a failure: restart
		// the log from the beginning (worst case: re-count a tail).
		return store.LogCursor{}, nil
	}
	return c, nil
}

// ApplyDeltas adds one flush batch in a single transaction: usage ledgers
// (day and month granularity), per-destination stats, last-seen stamps,
// and the log cursor. Upserts are additive, so a retry after a crash
// converges instead of double-counting (the cursor prevents re-reading
// the same bytes in the normal path).
func (r *AnalyticsRepository) ApplyDeltas(ctx context.Context, usage []store.UsageDelta, destinations []store.DestinationDelta, cursor store.LogCursor) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, u := range usage {
		for _, gran := range []struct{ period, gran string }{
			{u.Day, "day"}, {u.Month, "month"},
		} {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO usage_periods
					(user_id, period_start, granularity, bytes_in, bytes_out, connections)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (user_id, period_start, granularity) DO UPDATE SET
					bytes_in = bytes_in + excluded.bytes_in,
					bytes_out = bytes_out + excluded.bytes_out,
					connections = connections + excluded.connections`,
				u.UserID, gran.period, gran.gran, u.BytesIn, u.BytesOut, u.Connections); err != nil {
				return err
			}
		}
		if u.LastSeenUnix > 0 {
			seen := time.UnixMilli(u.LastSeenUnix).UTC()
			stamp := formatTime(seen)
			if _, err := tx.ExecContext(ctx, `
				UPDATE users SET last_seen_at = ?
				WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at < ?)`,
				stamp, u.UserID, stamp); err != nil {
				return err
			}
		}
	}

	for _, d := range destinations {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO destination_stats
				(user_id, day, host, port, protocol, requests, blocked, bytes_in, bytes_out, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (user_id, day, host, port, protocol) DO UPDATE SET
				requests = requests + excluded.requests,
				blocked = blocked + excluded.blocked,
				bytes_in = bytes_in + excluded.bytes_in,
				bytes_out = bytes_out + excluded.bytes_out,
				last_seen = excluded.last_seen`,
			d.UserID, d.Day, d.Host, d.Port, d.Protocol,
			d.Requests, d.Blocked, d.BytesIn, d.BytesOut, formatTime(d.LastSeen)); err != nil {
			return err
		}
	}

	raw, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
		cursorKey, string(raw)); err != nil {
		return err
	}

	return tx.Commit()
}

func (r *AnalyticsRepository) ListUserTraffic(ctx context.Context, userID int64, since time.Time) ([]store.UsagePeriod, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT period_start, granularity, bytes_in, bytes_out, connections
		FROM usage_periods
		WHERE user_id = ? AND granularity = 'day' AND period_start >= ?
		ORDER BY period_start`,
		userID, since.UTC().Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.UsagePeriod
	for rows.Next() {
		var p store.UsagePeriod
		var periodStart string
		if err := rows.Scan(&periodStart, &p.Granularity, &p.BytesIn, &p.BytesOut, &p.Connections); err != nil {
			return nil, err
		}
		day, err := time.Parse("2006-01-02", periodStart)
		if err != nil {
			return nil, err
		}
		p.PeriodStart = day
		out = append(out, p)
	}
	return out, rows.Err()
}

// globalTraffic is the day-summed traffic-history query shared by the
// per-user and global variants.
const globalTraffic = `
	SELECT period_start, SUM(bytes_in), SUM(bytes_out), SUM(connections)
	FROM usage_periods
	WHERE granularity = 'day' AND period_start >= ?`

func scanUsage(rows *sql.Rows) ([]store.UsagePeriod, error) {
	defer rows.Close()
	var out []store.UsagePeriod
	for rows.Next() {
		var p store.UsagePeriod
		var periodStart string
		if err := rows.Scan(&periodStart, &p.BytesIn, &p.BytesOut, &p.Connections); err != nil {
			return nil, err
		}
		day, err := time.Parse("2006-01-02", periodStart)
		if err != nil {
			return nil, err
		}
		p.PeriodStart = day
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *AnalyticsRepository) ListGlobalTraffic(ctx context.Context, since time.Time) ([]store.UsagePeriod, error) {
	rows, err := r.db.QueryContext(ctx, globalTraffic+`
		GROUP BY period_start ORDER BY period_start`,
		since.UTC().Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	return scanUsage(rows)
}

// destinationAgg is the shared SELECT for the grouped destination queries.
const destinationAgg = `
	SELECT u.username, d.host, d.port, d.protocol,
	       SUM(d.requests), SUM(d.blocked), SUM(d.bytes_in), SUM(d.bytes_out),
	       MAX(d.last_seen)
	FROM destination_stats d
	JOIN users u ON u.id = d.user_id`

func scanDestinations(rows *sql.Rows) ([]store.DestinationStat, error) {
	defer rows.Close()
	var out []store.DestinationStat
	for rows.Next() {
		var s store.DestinationStat
		var lastSeen string
		if err := rows.Scan(&s.Username, &s.Host, &s.Port, &s.Protocol,
			&s.Requests, &s.Blocked, &s.BytesIn, &s.BytesOut, &lastSeen); err != nil {
			return nil, err
		}
		var err error
		if s.LastSeen, err = parseTime(lastSeen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *AnalyticsRepository) ListUserDestinations(ctx context.Context, userID int64, sinceDay string, limit int) ([]store.DestinationStat, error) {
	rows, err := r.db.QueryContext(ctx, destinationAgg+`
		WHERE d.user_id = ? AND d.day >= ?
		GROUP BY d.host, d.port, d.protocol
		ORDER BY (SUM(d.bytes_in) + SUM(d.bytes_out)) DESC
		LIMIT ?`, userID, sinceDay, limit)
	if err != nil {
		return nil, err
	}
	return scanDestinations(rows)
}

func (r *AnalyticsRepository) ListTopDestinations(ctx context.Context, sinceDay string, limit int) ([]store.DestinationStat, error) {
	rows, err := r.db.QueryContext(ctx, destinationAgg+`
		WHERE d.day >= ?
		GROUP BY d.host, d.port, d.protocol
		ORDER BY (SUM(d.bytes_in) + SUM(d.bytes_out)) DESC
		LIMIT ?`, sinceDay, limit)
	if err != nil {
		return nil, err
	}
	return scanDestinations(rows)
}

func (r *AnalyticsRepository) ListBlockedDestinations(ctx context.Context, sinceDay string, limit int) ([]store.DestinationStat, error) {
	rows, err := r.db.QueryContext(ctx, destinationAgg+`
		WHERE d.day >= ? AND d.blocked > 0
		GROUP BY d.host, d.port, d.protocol
		ORDER BY SUM(d.blocked) DESC
		LIMIT ?`, sinceDay, limit)
	if err != nil {
		return nil, err
	}
	return scanDestinations(rows)
}

func (r *AnalyticsRepository) PruneDestinations(ctx context.Context, beforeDay string) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM destination_stats WHERE day < ?`, beforeDay)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ResetUsage zeroes the current quota window's ledger rows for one user:
// the day and month usage periods a reset targets. The engine's own
// counter (the enforcement mechanism) is reset separately; this keeps the
// dashboard's authoritative record in agreement.
func (r *AnalyticsRepository) ResetUsage(ctx context.Context, userID int64, day, month string) (int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		DELETE FROM usage_periods
		WHERE user_id = ? AND granularity = 'day' AND period_start >= ?`,
		userID, day)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	res, err = tx.ExecContext(ctx, `
		DELETE FROM usage_periods
		WHERE user_id = ? AND granularity = 'month' AND period_start >= ?`,
		userID, month)
	if err != nil {
		return 0, err
	}
	m, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	return n + m, tx.Commit()
}
