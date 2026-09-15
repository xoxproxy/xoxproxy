package deploy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/engine"
	"github.com/xoxproxy/xoxproxy/internal/store"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// fakeEngine is a scriptable stand-in for the engine deployer.
type fakeEngine struct {
	mu sync.Mutex
	// deploys counts Deploy calls; inFlight tracks overlapping calls
	// (single-flight proof: it must never exceed 1).
	deploys    int
	inFlight   int
	maxInFly   int
	results    []Result // returned in order, last one repeats
	err        error
	running    bool
	runningErr error
	// gate, when non-nil, holds each Deploy until closed.
	gate chan struct{}
	// states records every state handed to Deploy.
	states []engine.State
}

func (f *fakeEngine) Deploy(ctx context.Context, state engine.State) (Result, error) {
	f.mu.Lock()
	f.deploys++
	f.inFlight++
	if f.inFlight > f.maxInFly {
		f.maxInFly = f.inFlight
	}
	var res Result
	if len(f.results) > 0 {
		res = f.results[0]
		if len(f.results) > 1 {
			f.results = f.results[1:]
		}
	} else {
		res = Result{Changed: true, Reloaded: true, Checksum: "cafebabe"}
	}
	err := f.err
	gate := f.gate
	f.states = append(f.states, state)
	f.mu.Unlock()

	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return res, ctx.Err()
		}
	}

	f.mu.Lock()
	f.inFlight--
	f.mu.Unlock()
	return res, err
}

func (f *fakeEngine) Running() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running, f.runningErr
}

func (f *fakeEngine) stats() (deploys, maxInFly int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deploys, f.maxInFly
}

// newTestPipeline builds a pipeline over a real SQLite store with a fake
// engine and a state source that returns the given state.
func newTestPipeline(t *testing.T, eng Deployer, state engine.State) (*Service, *sqlite.DB) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditSvc := audit.New(logger, sqlite.NewAuditRepository(db))
	source := func(ctx context.Context, now time.Time) (engine.State, error) {
		return state, nil
	}
	svc := NewService(logger, eng, source, sqlite.NewConfigVersionRepository(db), auditSvc)
	return svc, db
}

func TestSingleFlightSerialization(t *testing.T) {
	eng := &fakeEngine{gate: make(chan struct{})}
	svc, db := newTestPipeline(t, eng, engine.State{})

	done := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, err := svc.DeployNow(context.Background(), "test", "concurrent")
			done <- err
		}()
	}
	// Let them all pile up on the mutex, then release the flood.
	time.Sleep(50 * time.Millisecond)
	close(eng.gate)
	for i := 0; i < 3; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	deploys, maxInFly := eng.stats()
	if deploys != 3 {
		t.Fatalf("deploys = %d, want 3", deploys)
	}
	if maxInFly != 1 {
		t.Fatalf("overlapping deploys peaked at %d, want 1 (single-flight violated)", maxInFly)
	}
	// Every deploy recorded its own generation.
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM configuration_versions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("configuration_versions rows = %d, want 3", n)
	}
}

func TestTriggerCoalescesWhileDeployRunning(t *testing.T) {
	eng := &fakeEngine{gate: make(chan struct{})}
	svc, db := newTestPipeline(t, eng, engine.State{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.Start(ctx)

	// First trigger starts a deploy that blocks on the gate.
	svc.Trigger("admin", "user.create:alice")
	time.Sleep(50 * time.Millisecond)
	// Five more triggers arrive while the first deploy is still running.
	for i := 0; i < 5; i++ {
		svc.Trigger("admin", fmt.Sprintf("user.update:%d", i))
	}
	close(eng.gate)

	// Exactly one follow-up deploy must run, carrying the first coalesced
	// reason; the four later triggers collapse into the same queued token.
	deadline := time.Now().Add(5 * time.Second)
	for {
		deploys, _ := eng.stats()
		if deploys >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("coalesced follow-up deploy never ran (deploys=%d)", deploys)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // let a would-be third deploy surface
	deploys, maxInFly := eng.stats()
	if deploys != 2 {
		t.Fatalf("deploys = %d, want exactly 2 (initial + one coalesced follow-up)", deploys)
	}
	if maxInFly != 1 {
		t.Fatalf("overlapping deploys peaked at %d, want 1", maxInFly)
	}
	var actor, reason string
	if err := db.QueryRowContext(context.Background(), `
		SELECT generated_by, reason FROM configuration_versions
		WHERE revision = (SELECT MAX(revision) FROM configuration_versions)`).
		Scan(&actor, &reason); err != nil {
		t.Fatal(err)
	}
	if actor != "admin" || reason != "user.update:0" {
		t.Fatalf("coalesced deploy recorded as %s/%q, want admin/%q (first reason of batch)",
			actor, reason, "user.update:0")
	}
}

func TestDeployOutcomeRecording(t *testing.T) {
	cases := []struct {
		name       string
		result     Result
		deployErr  error
		wantStatus string
	}{
		{"deployed", Result{Changed: true, Reloaded: true, Checksum: "aa"}, nil, store.DeploymentDeployed},
		{"deployed pending start", Result{Changed: true, Reloaded: false, Checksum: "bb"}, nil, store.DeploymentDeployed},
		{"unchanged", Result{Changed: false, Checksum: "cc"}, nil, store.DeploymentUnchanged},
		{"failed", Result{Checksum: ""}, errors.New("boom"), store.DeploymentFailed},
		{"rolled back", Result{Changed: true, RolledBack: true, Checksum: "dd"}, errors.New("engine died"), store.DeploymentRolledBack},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := &fakeEngine{results: []Result{tc.result}, err: tc.deployErr}
			svc, db := newTestPipeline(t, eng, engine.State{})
			_, err := svc.DeployNow(context.Background(), "admin", "user.create:alice")
			if (err != nil) != (tc.deployErr != nil) {
				t.Fatalf("DeployNow err = %v", err)
			}
			latest, err := sqlite.NewConfigVersionRepository(db).LatestConfigurationVersion(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if latest.DeploymentStatus != tc.wantStatus {
				t.Fatalf("deployment_status = %q, want %q", latest.DeploymentStatus, tc.wantStatus)
			}
			if latest.ValidationStatus != store.ValidationValid {
				t.Fatalf("validation_status = %q, want valid", latest.ValidationStatus)
			}
			if latest.Checksum != tc.result.Checksum {
				t.Fatalf("checksum = %q, want %q", latest.Checksum, tc.result.Checksum)
			}
			if latest.GeneratedBy != "admin" || latest.Reason != "user.create:alice" {
				t.Fatalf("recorded as %s/%q", latest.GeneratedBy, latest.Reason)
			}
		})
	}
}

func TestInvalidStateRejectedBeforeEngine(t *testing.T) {
	eng := &fakeEngine{}
	// A state that cannot be valid: duplicate record numbers.
	state := engine.State{Users: []engine.User{
		{Username: "alice", EngineHash: "$3$abc$0123456789012345678901", RecordNumber: 1, Protocols: []engine.Protocol{engine.ProtoHTTP}},
		{Username: "bob", EngineHash: "$3$abc$0123456789012345678901", RecordNumber: 1, Protocols: []engine.Protocol{engine.ProtoHTTP}},
	}}
	svc, db := newTestPipeline(t, eng, state)
	if _, err := svc.DeployNow(context.Background(), "admin", "test"); err == nil {
		t.Fatal("invalid state accepted")
	}
	deploys, _ := eng.stats()
	if deploys != 0 {
		t.Fatalf("deployer called %d times for an invalid state", deploys)
	}
	latest, err := sqlite.NewConfigVersionRepository(db).LatestConfigurationVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latest.ValidationStatus != store.ValidationInvalid || latest.DeploymentStatus != store.DeploymentFailed {
		t.Fatalf("recorded %s/%s, want invalid/failed", latest.ValidationStatus, latest.DeploymentStatus)
	}
}

func TestStateSourceFailureRecorded(t *testing.T) {
	eng := &fakeEngine{}
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditSvc := audit.New(logger, sqlite.NewAuditRepository(db))
	svc := NewService(logger, eng,
		func(ctx context.Context, now time.Time) (engine.State, error) {
			return engine.State{}, errors.New("database unavailable")
		},
		sqlite.NewConfigVersionRepository(db), auditSvc)

	if _, err := svc.DeployNow(context.Background(), "system", "startup"); err == nil {
		t.Fatal("source failure not surfaced")
	}
	deploys, _ := eng.stats()
	if deploys != 0 {
		t.Fatalf("deployer called %d times with no state", deploys)
	}
	latest, err := sqlite.NewConfigVersionRepository(db).LatestConfigurationVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latest.ValidationStatus != store.ValidationError || latest.DeploymentStatus != store.DeploymentFailed {
		t.Fatalf("recorded %s/%s, want error/failed", latest.ValidationStatus, latest.DeploymentStatus)
	}
}

// TestUsersStateSourceWiresEndToEnd proves the production state source
// (users -> BuildEngineState) feeds the pipeline: a created user reaches
// the deployer's state; disabling it does not.
func TestUsersStateSourceWiresEndToEnd(t *testing.T) {
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditSvc := audit.New(logger, sqlite.NewAuditRepository(db))
	usersSvc := users.NewService(logger,
		sqlite.NewUserRepository(db),
		sqlite.NewCredentialRepository(db),
		auditSvc)

	var triggerCount atomic.Int32
	usersSvc.SetStateChangeHook(func(actor, reason string) { triggerCount.Add(1) })

	eng := &fakeEngine{running: true}
	svc := NewService(logger, eng,
		UsersStateSource(sqlite.NewUserRepository(db)),
		sqlite.NewConfigVersionRepository(db), auditSvc)

	user, _, err := usersSvc.Create(context.Background(), users.CreateInput{
		Username: "alice", Protocols: []string{"http", "socks5"},
	}, users.Actor{Name: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if n := triggerCount.Load(); n != 1 {
		t.Fatalf("state-change hook fired %d times after create, want 1", n)
	}

	if _, err := svc.DeployNow(context.Background(), "admin", "user.create:alice"); err != nil {
		t.Fatal(err)
	}
	eng.mu.Lock()
	if len(eng.states) != 1 || len(eng.states[0].Users) != 1 || eng.states[0].Users[0].Username != "alice" {
		eng.mu.Unlock()
		t.Fatalf("deployed state does not contain alice: %+v", eng.states)
	}
	eng.mu.Unlock()

	if _, err := usersSvc.Disable(context.Background(), user.ID, user.Version, users.Actor{Name: "admin"}); err != nil {
		t.Fatal(err)
	}
	if n := triggerCount.Load(); n != 2 {
		t.Fatalf("state-change hook fired %d times after disable, want 2", n)
	}
	if _, err := svc.DeployNow(context.Background(), "admin", "user.disable:alice"); err != nil {
		t.Fatal(err)
	}
	eng.mu.Lock()
	last := eng.states[len(eng.states)-1]
	eng.mu.Unlock()
	if len(last.Users) != 0 {
		t.Fatalf("disabled user still in deployed state: %+v", last.Users)
	}
}

func TestStatusReporting(t *testing.T) {
	eng := &fakeEngine{running: true}
	svc, _ := newTestPipeline(t, eng, engine.State{})

	status, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.EngineRunning || status.LastDeploy != nil {
		t.Fatalf("status before any deploy: %+v", status)
	}

	if _, err := svc.DeployNow(context.Background(), "system", "startup"); err != nil {
		t.Fatal(err)
	}
	status, err = svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.EngineRunning || status.LastDeploy == nil {
		t.Fatalf("status after deploy: %+v", status)
	}
	if status.LastDeploy.Reason != "startup" || status.LastDeploy.GeneratedBy != "system" {
		t.Fatalf("last deploy recorded as %s/%q", status.LastDeploy.GeneratedBy, status.LastDeploy.Reason)
	}
}
