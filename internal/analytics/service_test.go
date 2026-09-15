package analytics

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/store"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// serviceHarness wires the full pipeline over a real SQLite store with a
// real (temp) traffic log, plus a pre-created proxy user "alice".
type serviceHarness struct {
	svc       *Service
	logPath   string
	db        *sqlite.DB
	usersSvc  *users.Service
	analytics *sqlite.AnalyticsRepository
}

func newServiceHarness(t *testing.T, opts Options) *serviceHarness {
	t.Helper()
	h, err := newHarness(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func newHarness(t *testing.T, opts Options) (*serviceHarness, error) {
	t.Helper()
	dir := t.TempDir()
	db, err := sqlite.Open(context.Background(), filepath.Join(dir, "t.db"))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		return nil, err
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	auditSvc := audit.New(logger, sqlite.NewAuditRepository(db))
	usersSvc := users.NewService(logger,
		sqlite.NewUserRepository(db),
		sqlite.NewCredentialRepository(db),
		auditSvc)
	if _, _, err := usersSvc.Create(context.Background(),
		users.CreateInput{Username: "alice", Protocols: []string{"http", "socks5"}},
		users.Actor{Name: "test"}); err != nil {
		return nil, err
	}

	logPath := filepath.Join(dir, "traffic.log")
	opts.LogPath = logPath
	if opts.PollInterval <= 0 {
		opts.PollInterval = 10 * time.Millisecond
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 50 * time.Millisecond
	}
	analyticsRepo := sqlite.NewAnalyticsRepository(db)
	svc := NewService(logger,
		analyticsRepo,
		sqlite.NewUserRepository(db),
		store.LogCursor{},
		opts)
	return &serviceHarness{svc: svc, logPath: logPath, db: db, usersSvc: usersSvc, analytics: analyticsRepo}, nil
}

// appendLog writes raw lines to the traffic log.
func (h *serviceHarness) appendLog(t *testing.T, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(h.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(f, l); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
}

// userID looks up a user's id; 0 when absent.
func (h *serviceHarness) userID(t *testing.T, username string) int64 {
	t.Helper()
	var id int64
	err := h.db.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&id)
	if err != nil {
		return 0
	}
	return id
}

// waitUntil polls cond until it holds or the deadline passes.
func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// pipeLine is a valid engine log line for user→host.
func pipeLine(ts int64, user, host string) string {
	return fmt.Sprintf("%d.0 proxy.3128 0 %s 10.0.0.1:40000 %s:443 100 900 0 CONNECT %s:443",
		ts, user, host, host)
}

func TestServicePipelinePersistsTraffic(t *testing.T) {
	h := newServiceHarness(t, Options{
		QueueSize:              100,
		RingSize:               10,
		MaxDestinationsPerUser: 10,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := h.svc.Done()
	go h.svc.Start(ctx)

	ts := time.Now().UTC().Add(-time.Minute).Unix()
	h.appendLog(t, pipeLine(ts, "alice", "example.com"), pipeLine(ts+1, "alice", "example.com"))

	waitUntil(t, 5*time.Second, func() bool {
		snap := h.svc.Live()
		return snap.Requests >= 2 && snap.Ingested >= 2
	}, "records to be ingested")

	// The final flush (on cancel) persists everything; wait for it.
	cancel()
	<-done

	// Cursor persisted at EOF.
	cursor, err := h.analytics.LoadCursor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cursor.Path != h.logPath || cursor.Offset == 0 {
		t.Fatalf("cursor = %+v", cursor)
	}

	// Live view and ring survived.
	if snap := h.svc.Live(); !snap.RingEnabled || snap.Dropped != 0 {
		t.Fatalf("live snapshot = %+v", snap)
	}
	if recs := h.svc.RecentConnections(10, "alice"); len(recs) != 2 {
		t.Fatalf("recent connections = %+v", recs)
	}

	// Persisted ledger: one day row with both connections.
	alice := h.userID(t, "alice")
	periods, err := h.svc.UserTraffic(context.Background(), alice, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(periods) != 1 || periods[0].Connections != 2 {
		t.Fatalf("usage periods = %+v", periods)
	}
	if periods[0].BytesIn != 1800 || periods[0].BytesOut != 200 {
		t.Fatalf("bytes = %+v", periods[0])
	}

	// Destination stats landed.
	dests, err := h.svc.UserDestinations(context.Background(), alice, "2000-01-01", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(dests) != 1 || dests[0].Host != "example.com" || dests[0].Requests != 2 {
		t.Fatalf("destinations = %+v", dests)
	}

	// last_seen was stamped on the user row.
	fresh, err := h.usersSvc.Get(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.LastSeenAt == nil {
		t.Fatal("users.last_seen_at was not updated")
	}
}

func TestServiceDropsUnknownUsersNotMisattributes(t *testing.T) {
	h := newServiceHarness(t, Options{
		QueueSize:              100,
		MaxDestinationsPerUser: 10,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := h.svc.Done()
	go h.svc.Start(ctx)

	ts := time.Now().UTC().Add(-time.Minute).Unix()
	// "ghost" has no user row; alice does.
	h.appendLog(t, pipeLine(ts, "ghost", "g.com"), pipeLine(ts+1, "alice", "a.com"))
	waitUntil(t, 5*time.Second, func() bool { return h.svc.Live().Ingested >= 2 }, "records ingested")
	cancel()
	<-done

	// Alice's traffic persisted; ghost's dropped, never attributed to
	// anyone else.
	alice := h.userID(t, "alice")
	periods, err := h.svc.UserTraffic(context.Background(), alice, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(periods) != 1 || periods[0].Connections != 1 {
		t.Fatalf("alice usage = %+v", periods)
	}
	if h.userID(t, "ghost") != 0 {
		t.Fatal("ghost must not exist")
	}
}

func TestServiceQueueFullDropsNotBlocks(t *testing.T) {
	h := newServiceHarness(t, Options{
		QueueSize:              2,
		MaxDestinationsPerUser: 10,
		// Slow flush so the queue can actually fill between polls.
		FlushInterval: time.Hour,
		PollInterval:  10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := h.svc.Done()
	go h.svc.Start(ctx)

	// Append far more lines than the queue holds in one poll.
	ts := time.Now().UTC().Add(-time.Minute).Unix()
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, pipeLine(ts+int64(i), "alice", fmt.Sprintf("h%d.com", i)))
	}
	h.appendLog(t, lines...)

	waitUntil(t, 5*time.Second, func() bool { return h.svc.Live().Dropped > 0 }, "drops to be counted")
	cancel()
	<-done
}
