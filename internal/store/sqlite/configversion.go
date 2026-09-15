package sqlite

import (
	"context"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// ConfigVersionRepository implements store.ConfigurationVersionRepository
// on SQLite. Rows are append-only by construction: only INSERT and SELECT
// exist here.
type ConfigVersionRepository struct {
	db *DB
}

func NewConfigVersionRepository(db *DB) *ConfigVersionRepository {
	return &ConfigVersionRepository{db: db}
}

const configVersionColumns = `
	revision, generated_at, generated_by, reason,
	validation_status, deployment_status, checksum`

func (r *ConfigVersionRepository) RecordConfigurationVersion(ctx context.Context, v store.ConfigurationVersion) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO configuration_versions
			(generated_at, generated_by, reason, validation_status, deployment_status, checksum)
		VALUES (?, ?, ?, ?, ?, ?)`,
		formatTime(v.GeneratedAt), v.GeneratedBy, v.Reason,
		v.ValidationStatus, v.DeploymentStatus, v.Checksum)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *ConfigVersionRepository) ListConfigurationVersions(ctx context.Context, limit int) ([]store.ConfigurationVersion, error) {
	if limit < 1 {
		limit = 1
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT`+configVersionColumns+`
		FROM configuration_versions
		ORDER BY revision DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.ConfigurationVersion
	for rows.Next() {
		v, err := scanConfigVersion(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *ConfigVersionRepository) LatestConfigurationVersion(ctx context.Context) (store.ConfigurationVersion, error) {
	v, err := scanConfigVersion(func(dest ...any) error {
		return r.db.QueryRowContext(ctx, `
			SELECT`+configVersionColumns+`
			FROM configuration_versions
			ORDER BY revision DESC
			LIMIT 1`).Scan(dest...)
	})
	if err != nil {
		if isNoRows(err) {
			return store.ConfigurationVersion{}, store.ErrNotFound
		}
		return store.ConfigurationVersion{}, err
	}
	return v, nil
}

func scanConfigVersion(scan func(dest ...any) error) (store.ConfigurationVersion, error) {
	var v store.ConfigurationVersion
	var generatedAt string
	if err := scan(&v.Revision, &generatedAt, &v.GeneratedBy, &v.Reason,
		&v.ValidationStatus, &v.DeploymentStatus, &v.Checksum); err != nil {
		return store.ConfigurationVersion{}, err
	}
	var err error
	if v.GeneratedAt, err = parseTime(generatedAt); err != nil {
		return store.ConfigurationVersion{}, err
	}
	return v, nil
}
