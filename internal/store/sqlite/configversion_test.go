package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

func newConfigVersionRepo(t *testing.T) (*ConfigVersionRepository, *DB) {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return NewConfigVersionRepository(db), db
}

func TestConfigVersionRepositoryHistory(t *testing.T) {
	repo, _ := newConfigVersionRepo(t)
	ctx := context.Background()

	if _, err := repo.LatestConfigurationVersion(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("latest on empty history = %v, want ErrNotFound", err)
	}

	base := time.Now().UTC().Add(-time.Hour)
	rows := []store.ConfigurationVersion{
		{GeneratedAt: base, GeneratedBy: "system", Reason: "startup",
			ValidationStatus: store.ValidationValid, DeploymentStatus: store.DeploymentDeployed, Checksum: "aa11"},
		{GeneratedAt: base.Add(time.Minute), GeneratedBy: "admin", Reason: "user.create:alice",
			ValidationStatus: store.ValidationValid, DeploymentStatus: store.DeploymentUnchanged, Checksum: "aa11"},
		{GeneratedAt: base.Add(2 * time.Minute), GeneratedBy: "admin", Reason: "user.create:bob",
			ValidationStatus: store.ValidationValid, DeploymentStatus: store.DeploymentRolledBack, Checksum: "bb22"},
	}
	for i, row := range rows {
		rev, err := repo.RecordConfigurationVersion(ctx, row)
		if err != nil {
			t.Fatal(err)
		}
		if rev != int64(i+1) {
			t.Fatalf("revision = %d, want %d", rev, i+1)
		}
	}

	latest, err := repo.LatestConfigurationVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Reason != "user.create:bob" || latest.DeploymentStatus != store.DeploymentRolledBack {
		t.Fatalf("latest = %+v", latest)
	}
	if !latest.GeneratedAt.Equal(rows[2].GeneratedAt) {
		t.Fatalf("generated_at not round-tripped: %v vs %v", latest.GeneratedAt, rows[2].GeneratedAt)
	}

	list, err := repo.ListConfigurationVersions(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Revision != 3 || list[1].Revision != 2 {
		t.Fatalf("list not newest-first: %+v", list)
	}
}
