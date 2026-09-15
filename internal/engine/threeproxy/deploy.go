package threeproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/engine"
)

// previousExt marks the last-known-good config, restored on rollback
// and by a systemd restart after a config that kills the engine.
const previousExt = ".prev"

// DeployResult reports what a Deploy actually did.
type DeployResult struct {
	// Changed is true when the rendered config differed from the
	// on-disk config and was replaced (and the engine reloaded).
	Changed bool
	// Reloaded is true when a SIGUSR1 was delivered.
	Reloaded bool
	// RolledBack is true when the engine died after the reload and the
	// previous config was restored (or the bad config removed). The
	// returned error describes the failure.
	RolledBack bool
	// Checksum is the SHA-256 of the rendered config, set on every
	// outcome (including unchanged) so the pipeline can record it in
	// configuration_versions.
	Checksum string
}

// ErrEngineNotRunning is returned when the engine PID file is missing
// or stale; the deploy still wrote the config, so a (re)start of the
// engine service picks it up.
var ErrEngineNotRunning = errors.New("engine process not running")

// Deployer renders, atomically installs, and reload-reapplies engine
// configuration. The data plane reads only the config file; nothing
// here touches the control-plane database on the traffic path.
//
// The three process-level operations (alive check, identity check,
// signal) are fields so tests can drive the full pipeline — including
// rollback — without a real engine process.
type Deployer struct {
	settings Settings
	logger   *slog.Logger

	procAliveFn   func(pid int) bool
	pidIsEngineFn func(pid int) error
	signalFn      func(pid int) error

	// verifyWindow/verifyTick bound post-reload health checking; the
	// engine applies a reload within ~1 s (listener poll cycle).
	// Tests shrink both.
	verifyWindow time.Duration
	verifyTick   time.Duration
}

// NewDeployer validates the settings once; every subsequent Deploy is
// safe to assume them renderable.
func NewDeployer(st Settings, logger *slog.Logger) (*Deployer, error) {
	if err := st.Validate(); err != nil {
		return nil, fmt.Errorf("threeproxy: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Deployer{
		settings:      st,
		logger:        logger,
		procAliveFn:   procAlive,
		pidIsEngineFn: pidIsEngine,
		signalFn:      signalReload,
		verifyWindow:  3 * time.Second,
		verifyTick:    200 * time.Millisecond,
	}, nil
}

// Settings returns the deployer's (already validated) settings.
func (d *Deployer) Settings() Settings { return d.settings }

// Deploy renders the state and installs it as the engine config:
//
//  1. render + validate (injection-safe; Render re-validates inputs)
//  2. if the on-disk config is byte-identical: nothing to do
//  3. back up the current config to <config>.prev
//  4. atomically replace the config (temp file + fsync + rename)
//  5. SIGUSR1 the engine (never SIGHUP — that terminates 3proxy; see
//     docs/SPIKE-3PROXY.md §1.1)
//  6. verify the engine survived the reload; if not, restore the
//     previous config so the next engine (re)start comes up clean and
//     report the failure
//
// Reload semantics (verified): listeners are replaced within ~1 s,
// established connections are force-re-authenticated against the new
// config, so removed users lose connectivity at their next I/O.
func (d *Deployer) Deploy(ctx context.Context, state engine.State) (DeployResult, error) {
	rendered, err := Render(state, d.settings)
	if err != nil {
		return DeployResult{}, err
	}
	sum := sha256.Sum256([]byte(rendered))
	checksum := hex.EncodeToString(sum[:])

	current, readErr := os.ReadFile(d.settings.ConfigFile)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return DeployResult{}, fmt.Errorf("threeproxy: read current config: %w", readErr)
	}
	if readErr == nil && string(current) == rendered {
		return DeployResult{Changed: false, Checksum: checksum}, nil
	}

	if err := os.MkdirAll(filepath.ToSlash(filepath.Dir(d.settings.ConfigFile)), 0o750); err != nil {
		return DeployResult{}, fmt.Errorf("threeproxy: create config dir: %w", err)
	}

	// Keep the last-known-good config before touching the live one.
	if readErr == nil {
		if err := writeAtomic(d.settings.ConfigFile+previousExt, current, 0o600); err != nil {
			return DeployResult{}, fmt.Errorf("threeproxy: back up current config: %w", err)
		}
	}

	if err := writeAtomic(d.settings.ConfigFile, []byte(rendered), 0o600); err != nil {
		return DeployResult{}, fmt.Errorf("threeproxy: install config: %w", err)
	}

	pid, err := d.enginePID()
	if err != nil {
		// Config is on disk; a not-yet-running engine (first install,
		// crashed engine) starts with it. Not a deploy failure.
		d.logger.Warn("engine not running; config will apply on next start",
			slog.String("config", d.settings.ConfigFile),
			slog.String("error", err.Error()))
		return DeployResult{Changed: true, Checksum: checksum}, nil
	}

	if err := d.reload(ctx, pid); err != nil {
		if errors.Is(err, ErrEngineNotRunning) {
			return DeployResult{Changed: true, Checksum: checksum}, nil
		}
		return DeployResult{Changed: true, Checksum: checksum}, fmt.Errorf("threeproxy: reload: %w", err)
	}

	// The engine applies the reload within ~1 s (listener poll cycle).
	// If the new config kills it (parse refusal is fail-stopped), the
	// PID disappears: restore the previous config so systemd's restart
	// comes up with last-known-good state.
	if err := d.verifyAfterReload(ctx, pid); err != nil {
		d.logger.Error("engine unhealthy after reload; rolling back config",
			slog.String("error", err.Error()))
		if readErr == nil {
			if rbErr := writeAtomic(d.settings.ConfigFile, current, 0o600); rbErr != nil {
				return DeployResult{Changed: true, RolledBack: true, Checksum: checksum},
					fmt.Errorf("threeproxy: verify: %w (rollback failed: %v)", err, rbErr)
			}
		} else {
			// No previous config existed; remove the bad one so the
			// engine does not restart into a config we know is bad.
			if rmErr := os.Remove(d.settings.ConfigFile); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				return DeployResult{Changed: true, RolledBack: true, Checksum: checksum},
					fmt.Errorf("threeproxy: verify: %w (cleanup failed: %v)", err, rmErr)
			}
		}
		return DeployResult{Changed: true, RolledBack: true, Checksum: checksum},
			fmt.Errorf("threeproxy: engine unhealthy after reload, previous config restored: %w", err)
	}

	return DeployResult{Changed: true, Reloaded: true, Checksum: checksum}, nil
}

// verifyAfterReload waits out the reload cycle and confirms the engine
// process is still alive.
func (d *Deployer) verifyAfterReload(ctx context.Context, pid int) error {
	deadline := time.Now().Add(d.verifyWindow)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if !d.procAliveFn(pid) {
			return fmt.Errorf("engine process %d exited after reload", pid)
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(d.verifyTick)
	}
}

// enginePID reads and validates the engine PID from the pid file.
func (d *Deployer) enginePID() (int, error) {
	data, err := os.ReadFile(d.settings.PidFile)
	if err != nil {
		return 0, fmt.Errorf("%w: read pid file: %v", ErrEngineNotRunning, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid < 2 {
		return 0, fmt.Errorf("%w: pid file contents %q", ErrEngineNotRunning, string(data))
	}
	if !d.procAliveFn(pid) {
		return 0, fmt.Errorf("%w: stale pid %d", ErrEngineNotRunning, pid)
	}
	return pid, nil
}

// Running reports whether the engine process is up.
func (d *Deployer) Running() (bool, error) {
	_, err := d.enginePID()
	if err != nil {
		if errors.Is(err, ErrEngineNotRunning) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// reload sends SIGUSR1 to the engine after confirming the PID really
// belongs to the engine binary. SIGUSR1's default action for unrelated
// processes is termination — signaling a recycled PID would kill an
// innocent process, so verification is mandatory, not an optimization.
func (d *Deployer) reload(ctx context.Context, pid int) error {
	if err := d.pidIsEngineFn(pid); err != nil {
		return fmt.Errorf("%w: pid %d: %v", ErrEngineNotRunning, pid, err)
	}
	if err := d.signalFn(pid); err != nil {
		return err
	}
	d.logger.Info("engine reload signalled", slog.Int("pid", pid))
	return nil
}

// writeAtomic replaces path's contents atomically: write a temp file in
// the same directory, fsync it, rename over the target, fsync the
// directory. A crash mid-write can never leave a partial config — the
// engine either sees the old file or the new one.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".xox-deploy-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// No-op after successful rename.
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}

	// Persist the directory entry. Best effort: some platforms (and
	// filesystems) do not support syncing directories.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
