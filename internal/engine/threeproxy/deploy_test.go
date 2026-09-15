package threeproxy

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/engine"
)

// fakeEngine simulates the engine process for pipeline tests: a PID
// file plus hooks that record what the deployer did to "the process".
type fakeEngine struct {
	t        *testing.T
	pidFile  string
	pid      int
	identity error // returned by pidIsEngineFn; nil = looks like 3proxy
	signals  []string
	// dieOnSignal makes the fake process exit when signalled (config
	// refused).
	dieOnSignal bool
	alive       bool
}

func newFakeEngine(t *testing.T, dir string) *fakeEngine {
	t.Helper()
	fe := &fakeEngine{t: t, pidFile: filepath.Join(dir, "3proxy.pid"), pid: 4242, alive: true}
	fe.writePID()
	return fe
}

func (fe *fakeEngine) writePID() {
	if err := os.WriteFile(fe.pidFile, []byte(strconv.Itoa(fe.pid)), 0o600); err != nil {
		fe.t.Fatal(err)
	}
}

func (fe *fakeEngine) attach(d *Deployer) {
	d.procAliveFn = func(pid int) bool { return pid == fe.pid && fe.alive }
	d.pidIsEngineFn = func(pid int) error {
		if pid != fe.pid {
			return errors.New("no such process")
		}
		return fe.identity
	}
	d.signalFn = func(pid int) error {
		if pid != fe.pid {
			return errors.New("no such process")
		}
		fe.signals = append(fe.signals, "USR1")
		if fe.dieOnSignal {
			fe.alive = false
		}
		return nil
	}
	// Keep the test fast.
	d.verifyWindow = 150 * time.Millisecond
	d.verifyTick = 20 * time.Millisecond
}

func tempSettings(t *testing.T) (Settings, string) {
	t.Helper()
	dir := t.TempDir()
	return Settings{
		ConfigFile:  filepath.Join(dir, "3proxy.cfg"),
		PidFile:     filepath.Join(dir, "3proxy.pid"),
		CounterFile: filepath.Join(dir, "counters.3cf"),
		LogFile:     filepath.Join(dir, "traffic.log"),
		HTTPPort:    3128,
		SOCKS5Port:  1080,
	}, dir
}

func TestDeployFirstInstallWithoutEngine(t *testing.T) {
	st, _ := tempSettings(t)
	d, err := NewDeployer(st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	res, err := d.Deploy(context.Background(), validState(t))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Reloaded {
		t.Fatalf("first install: %+v", res)
	}
	if _, err := os.Stat(st.ConfigFile); err != nil {
		t.Fatal("config not written")
	}
	// No previous config existed: no .prev file must be left behind.
	if _, err := os.Stat(st.ConfigFile + previousExt); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".prev file created on first install")
	}
}

func TestDeployIdempotentWhenUnchanged(t *testing.T) {
	st, _ := tempSettings(t)
	d, err := NewDeployer(st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	fe := newFakeEngine(t, filepath.Dir(st.PidFile))
	fe.attach(d)

	if _, err := d.Deploy(context.Background(), validState(t)); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(st.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	res, err := d.Deploy(context.Background(), validState(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Error("unchanged state reported as changed")
	}
	if len(fe.signals) != 1 {
		// One signal from the initial install above, none for the
		// identical re-deploy.
		t.Errorf("identical re-deploy signalled the engine (total %d, want 1)", len(fe.signals))
	}
	after, err := os.Stat(st.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("config rewritten for identical state")
	}
}

func TestDeployReloadsEngineOnChange(t *testing.T) {
	st, _ := tempSettings(t)
	d, err := NewDeployer(st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	fe := newFakeEngine(t, filepath.Dir(st.PidFile))
	fe.attach(d)

	state := validState(t)
	if _, err := d.Deploy(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	state.Users = state.Users[:1] // remove bob
	res, err := d.Deploy(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || !res.Reloaded {
		t.Fatalf("changed state: %+v", res)
	}
	if len(fe.signals) != 2 {
		t.Fatalf("engine signalled %d times, want 2 (install + change)", len(fe.signals))
	}

	// The .prev backup holds the previous (two-user) config.
	prev, err := os.ReadFile(st.ConfigFile + previousExt)
	if err != nil {
		t.Fatal(err)
	}
	if !containsUser(prev, "bob") {
		t.Error("previous config backup lost bob")
	}
	cur, err := os.ReadFile(st.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if containsUser(cur, "bob") {
		t.Error("removed user still in live config")
	}
}

func containsUser(cfg []byte, name string) bool {
	return strings.Contains(string(cfg), "allow "+name+"\n")
}

func TestDeployRollsBackWhenEngineDies(t *testing.T) {
	st, _ := tempSettings(t)
	d, err := NewDeployer(st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	fe := newFakeEngine(t, filepath.Dir(st.PidFile))
	fe.attach(d)

	state := validState(t)
	if _, err := d.Deploy(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	fe.dieOnSignal = true // engine refuses the NEXT config and exits

	state.Users = state.Users[:1]
	_, err = d.Deploy(context.Background(), state)
	if err == nil {
		t.Fatal("deploy succeeded although the engine died")
	}

	// Rollback: live config must be the previous one again.
	cur, err := os.ReadFile(st.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !containsUser(cur, "bob") {
		t.Error("rollback did not restore the previous config")
	}
	if containsUser(cur, "countall 1 M 100 alice") && !containsUser(cur, "allow bob") {
		t.Error("live config is not the pre-deploy version")
	}
}

func TestDeployRefusesToSignalForeignProcess(t *testing.T) {
	st, _ := tempSettings(t)
	d, err := NewDeployer(st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	fe := newFakeEngine(t, filepath.Dir(st.PidFile))
	fe.identity = errors.New("pid 4242 is nginx, not 3proxy")
	fe.attach(d)

	state := validState(t)
	if _, err := d.Deploy(context.Background(), state); err != nil {
		t.Fatal(err) // first deploy: pid file did not exist yet? it does
	}
	// Now a changed state must NOT be signalled at a foreign process.
	state.Users = state.Users[:1]
	res, err := d.Deploy(context.Background(), state)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if res.Reloaded {
		t.Error("deploy signalled a process it could not identify as 3proxy")
	}
	if len(fe.signals) != 0 {
		t.Error("signal delivered to foreign process")
	}
	// The config is still installed; the engine applies it on restart.
	if _, err := os.Stat(st.ConfigFile); err != nil {
		t.Error("config not left in place for next start")
	}
}

func TestDeployRejectsInvalidStateBeforeTouchingDisk(t *testing.T) {
	st, _ := tempSettings(t)
	d, err := NewDeployer(st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	state := engine.State{Users: []engine.User{
		{Username: "bad\nusers root:CL:x", EngineHash: hashFor(t, "pw-long-enough-1"), RecordNumber: 1},
	}}
	if _, err := d.Deploy(context.Background(), state); err == nil {
		t.Fatal("hostile state deployed")
	}
	if _, err := os.Stat(st.ConfigFile); !errors.Is(err, os.ErrNotExist) {
		t.Error("invalid state wrote a config file")
	}
}

func TestStalePIDFileMeansEngineNotRunning(t *testing.T) {
	st, _ := tempSettings(t)
	if err := os.WriteFile(st.PidFile, []byte("999999999"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := NewDeployer(st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	d.procAliveFn = func(int) bool { return false }

	running, err := d.Running()
	if err != nil || running {
		t.Fatalf("Running() = %v, %v; want false, nil", running, err)
	}
	res, err := d.Deploy(context.Background(), validState(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Reloaded {
		t.Error("deploy claims reload with stale pid")
	}
	if !res.Changed {
		t.Error("config should still be installed")
	}
}
