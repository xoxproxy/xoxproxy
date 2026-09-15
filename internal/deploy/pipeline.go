// Package deploy orchestrates configuration generation and safe reload:
// it derives the desired engine state from the store, renders and deploys
// it through the engine provider, and records every generation in
// configuration_versions.
//
// Concurrency contract (GUIDE: "do not allow two simultaneous
// configuration deployments to race"): DeployNow is single-flight — a
// mutex serializes deployments process-wide, so an API mutation, a CLI
// command, the expiry sweep, and the startup reconcile can all fire
// without ever interleaving two config writes or two SIGUSR1s. Trigger
// additionally coalesces: triggers arriving while a deploy runs collapse
// into one follow-up deploy, so a burst of mutations produces one reload,
// not ten.
//
// The pipeline is the only writer of the engine config. Rollback is the
// deployer's responsibility (restore .prev when the engine dies after a
// reload); the pipeline records the outcome and never retries a failed
// deploy on its own — the next trigger re-derives state from the store,
// which is the source of truth.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/engine"
	"github.com/xoxproxy/xoxproxy/internal/engine/threeproxy"
	"github.com/xoxproxy/xoxproxy/internal/store"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// Result mirrors the engine deployer's outcome for callers of the
// pipeline. Checksum is the SHA-256 of the rendered config ("" when
// nothing was rendered).
type Result struct {
	Changed    bool
	Reloaded   bool
	RolledBack bool
	Checksum   string
}

// Deployer is the engine-facing contract of the pipeline. The production
// implementation is *threeproxy.Deployer (see NewThreeproxy); tests
// substitute their own.
type Deployer interface {
	Deploy(ctx context.Context, state engine.State) (Result, error)
	// Running reports whether the engine process is up (for status
	// reporting — never a readiness check; an engine problem must not
	// take the control plane with it).
	Running() (bool, error)
}

// NewThreeproxy adapts the 3proxy deployer to the pipeline's Deployer
// contract.
func NewThreeproxy(d *threeproxy.Deployer) Deployer {
	return threeproxyAdapter{d: d}
}

type threeproxyAdapter struct{ d *threeproxy.Deployer }

func (a threeproxyAdapter) Deploy(ctx context.Context, state engine.State) (Result, error) {
	r, err := a.d.Deploy(ctx, state)
	return Result{
		Changed:    r.Changed,
		Reloaded:   r.Reloaded,
		RolledBack: r.RolledBack,
		Checksum:   r.Checksum,
	}, err
}

func (a threeproxyAdapter) Running() (bool, error) { return a.d.Running() }

// StateSource derives the desired engine state. It is a function type so
// the pipeline stays decoupled from where state comes from; the v1 source
// is UsersStateSource.
type StateSource func(ctx context.Context, now time.Time) (engine.State, error)

// UsersStateSource derives the desired state from the proxy-user store:
// every active, unexpired user with the engine hash of its active
// credential. This is the only state source in v1.
func UsersStateSource(repo store.UserRepository) StateSource {
	return func(ctx context.Context, now time.Time) (engine.State, error) {
		rows, err := repo.ListEngineUsers(ctx, now)
		if err != nil {
			return engine.State{}, err
		}
		return users.BuildEngineState(rows, now), nil
	}
}

// Service is the deploy pipeline.
type Service struct {
	deployer Deployer
	source   StateSource
	versions store.ConfigurationVersionRepository
	audit    *audit.Service
	logger   *slog.Logger
	now      func() time.Time

	// deployMu is the single-flight lock: one deployment at a time,
	// process-wide, across API, CLI, sweep, and startup callers.
	deployMu sync.Mutex

	// wake carries coalesced trigger requests to the worker (Start).
	wake chan struct{}

	reasonMu   sync.Mutex
	nextReason string
	nextActor  string
}

// NewService builds the pipeline. versions and audit may share one
// database handle with the state source; the pipeline performs no
// cross-table transactions.
func NewService(logger *slog.Logger, deployer Deployer, source StateSource, versions store.ConfigurationVersionRepository, auditSvc *audit.Service) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		deployer: deployer,
		source:   source,
		versions: versions,
		audit:    auditSvc,
		logger:   logger,
		now:      time.Now,
		wake:     make(chan struct{}, 1),
	}
}

// Trigger requests a redeploy without blocking the caller (an HTTP
// handler must not sit through the post-reload verify window). Triggers
// arriving while a deploy is running coalesce into one follow-up deploy;
// the first reason of a batch wins, since it names the change that
// started it.
func (s *Service) Trigger(actor, reason string) {
	s.reasonMu.Lock()
	if s.nextReason == "" {
		s.nextActor, s.nextReason = actor, reason
	}
	s.reasonMu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default: // a trigger is already queued; its reason is recorded
	}
}

// Start runs the trigger worker until ctx is cancelled. DeployNow remains
// callable directly (CLI, startup) — the single-flight lock, not the
// worker, provides the mutual exclusion.
func (s *Service) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			s.reasonMu.Lock()
			actor, reason := s.nextActor, s.nextReason
			s.nextActor, s.nextReason = "", ""
			s.reasonMu.Unlock()
			if reason == "" {
				actor, reason = "system", "state-change"
			}
			if _, err := s.DeployNow(ctx, actor, reason); err != nil {
				s.logger.Error("triggered deploy failed",
					slog.String("reason", reason),
					slog.String("error", err.Error()))
			}
		}
	}
}

// DeployNow synchronously derives, deploys, and records one generation.
// Single-flight: a concurrent caller blocks until the in-flight deploy
// finishes, then runs its own.
func (s *Service) DeployNow(ctx context.Context, actor, reason string) (Result, error) {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()

	now := s.now().UTC()

	state, err := s.source(ctx, now)
	if err != nil {
		s.record(ctx, actor, reason, store.ValidationError, store.DeploymentFailed, "", now)
		return Result{}, fmt.Errorf("deploy: derive state: %w", err)
	}
	// Defense in depth: the deployer re-validates inside Render, but a
	// bad state is recorded as invalid rather than failed if we can catch
	// it here first.
	if err := state.Validate(); err != nil {
		s.record(ctx, actor, reason, store.ValidationInvalid, store.DeploymentFailed, "", now)
		return Result{}, fmt.Errorf("deploy: invalid state: %w", err)
	}

	res, err := s.deployer.Deploy(ctx, state)
	status := store.DeploymentDeployed
	switch {
	case err != nil && res.RolledBack:
		status = store.DeploymentRolledBack
	case err != nil:
		status = store.DeploymentFailed
	case !res.Changed:
		status = store.DeploymentUnchanged
	}
	s.recordOutcome(ctx, actor, reason, status, res, now)

	if err != nil {
		return res, fmt.Errorf("deploy: %w", err)
	}
	return res, nil
}

// recordOutcome records a deploy that produced a result; record covers
// the pre-deploy failure paths.
func (s *Service) recordOutcome(ctx context.Context, actor, reason, status string, res Result, now time.Time) {
	detail := fmt.Sprintf("%s, checksum %s", status, res.Checksum)
	if status == store.DeploymentDeployed && !res.Reloaded {
		detail += ", engine not running (applies on next start)"
	}
	if res.RolledBack {
		detail += ", previous config restored"
	}
	s.recordRow(ctx, actor, reason, store.ValidationValid, status, res.Checksum, detail, now)
}

func (s *Service) record(ctx context.Context, actor, reason, validation, deployment, checksum string, now time.Time) {
	detail := deployment
	if checksum != "" {
		detail += ", checksum " + checksum
	}
	s.recordRow(ctx, actor, reason, validation, deployment, checksum, detail, now)
}

// recordRow appends the configuration_versions row and the audit entry.
// The rendered config itself is never persisted or audited — it contains
// credential verifiers; only the checksum is recorded.
func (s *Service) recordRow(ctx context.Context, actor, reason, validation, deployment, checksum, detail string, now time.Time) {
	revision, err := s.versions.RecordConfigurationVersion(ctx, store.ConfigurationVersion{
		GeneratedAt:      now,
		GeneratedBy:      actor,
		Reason:           reason,
		ValidationStatus: validation,
		DeploymentStatus: deployment,
		Checksum:         checksum,
	})
	if err != nil {
		s.logger.Error("record configuration version failed",
			slog.String("reason", reason),
			slog.String("error", err.Error()))
	}
	s.auditRecord(ctx, actor, reason, deployment, revision, detail)
}

func (s *Service) auditRecord(ctx context.Context, actor, reason, deployment string, revision int64, detail string) {
	result := "success"
	if deployment == store.DeploymentFailed || deployment == store.DeploymentRolledBack {
		result = "failure"
	}
	if revision > 0 {
		detail = fmt.Sprintf("revision %d, %s", revision, detail)
	}
	if err := s.audit.Record(ctx, store.AuditEntry{
		Actor:  actor,
		Action: "config.deploy",
		Target: reason,
		Result: result,
		Detail: detail,
	}); err != nil {
		s.logger.Error("config deploy audit failed", slog.String("error", err.Error()))
	}
}

// --- status reporting ---

// Status is the operational view of the pipeline for the API: whether the
// engine is running and what the last generation did.
type Status struct {
	EngineRunning bool
	LastDeploy    *store.ConfigurationVersion // nil when nothing deployed yet
}

// Status reports engine running state and the latest recorded generation.
func (s *Service) Status(ctx context.Context) (Status, error) {
	running, err := s.deployer.Running()
	if err != nil {
		return Status{}, err
	}
	latest, err := s.versions.LatestConfigurationVersion(ctx)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Status{EngineRunning: running}, nil
		}
		return Status{}, err
	}
	return Status{EngineRunning: running, LastDeploy: &latest}, nil
}

// ListVersions returns the newest configuration generations first.
func (s *Service) ListVersions(ctx context.Context, limit int) ([]store.ConfigurationVersion, error) {
	return s.versions.ListConfigurationVersions(ctx, limit)
}
