// Package sqlite is the SQLite implementation of the store interfaces
// (single-node deployment; see ARCHITECTURE.md §7). It uses the pure-Go
// modernc.org/sqlite driver so release binaries stay static and
// cross-compilable with CGO_ENABLED=0.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	// Pure-Go SQLite driver; registers database/sql driver name "sqlite".
	// Kept static (no CGO) for reproducible cross-compiled releases.
	_ "modernc.org/sqlite"
)

// DriverName is the registered modernc.org/sqlite driver.
const DriverName = "sqlite"

// DB wraps *sql.DB with xoxproxy's SQLite policy.
//
// Concurrency: MaxOpenConns(1). WAL mode permits concurrent readers in
// general, but a single connection removes SQLITE_BUSY contention entirely
// and serializes the small write volume of a control plane predictably.
// Analytics batching (Phase 7) keeps writes low-frequency.
type DB struct {
	*sql.DB
}

// Open opens (creating if needed) the database at path and applies the
// connection pragmas: WAL journaling, NORMAL sync (durable enough for
// transactional consistency with WAL), busy timeout, and enforced foreign
// keys on every connection.
func Open(ctx context.Context, path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("sqlite: create data dir: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=busy_timeout(10000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"
	sqlDB, err := sql.Open(DriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxIdleTime(0)
	sqlDB.SetConnMaxLifetime(0)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	return &DB{sqlDB}, nil
}

// --- migrations ---

//go:embed migrations/*.sql
var migrationFS embed.FS

var migrationNameRe = regexp.MustCompile(`^(\d+)_.*\.sql$`)

// Migrate applies pending forward-only migrations. Each migration runs in
// one transaction together with its schema_migrations insert, so a crashed
// migrate leaves the database at a clean version boundary.
func (db *DB) Migrate(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("sqlite: migrations bootstrap: %w", err)
	}

	var current int
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("sqlite: read migration version: %w", err)
	}

	pending, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, m := range pending {
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("sqlite: migration %04d: %w", m.version, err)
		}
	}
	return nil
}

type migration struct {
	version    int
	name       string
	statements []string
}

func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("sqlite: read migrations: %w", err)
	}
	var migrations []migration
	for _, e := range entries {
		m := migrationNameRe.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("sqlite: migration file %q does not match NNNN_name.sql", e.Name())
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("sqlite: bad migration version in %q: %w", e.Name(), err)
		}
		data, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("sqlite: read migration %q: %w", e.Name(), err)
		}
		migrations = append(migrations, migration{
			version:    v,
			name:       e.Name(),
			statements: splitStatements(string(data)),
		})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	return migrations, nil
}

// splitStatements splits a migration into individual statements: comment
// lines are stripped, the remainder is split on ";". Migration files
// therefore must not contain semicolons inside string literals — enforced
// by convention and reviewed at PR time; a full SQL parser is not warranted
// for files we author ourselves.
func splitStatements(s string) []string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	var stmts []string
	for _, stmt := range strings.Split(b.String(), ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

func applyMigration(ctx context.Context, db *DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range m.statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("statement %q: %w", firstLine(stmt), err)
		}
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		m.version, formatTime(time.Now().UTC()))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// --- shared helpers for repositories ---

const timeLayout = time.RFC3339Nano

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("sqlite: parse timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

// parseNullTime handles NULL timestamp columns.
func parseNullTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Ping verifies the database connection; used as the /health/ready check.
func (db *DB) Ping(ctx context.Context) error {
	var one int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("sqlite ping: %w", err)
	}
	return nil
}
