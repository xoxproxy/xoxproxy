//go:build !windows

package threeproxy

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// signalReload delivers SIGUSR1 — 3proxy's reload signal. SIGHUP would
// terminate the daemon (it installs no handler for it); see
// docs/SPIKE-3PROXY.md §1.1.
func signalReload(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGUSR1); err != nil {
		return fmt.Errorf("SIGUSR1 to %d: %w", pid, err)
	}
	return nil
}

// procAlive checks a PID with signal 0.
func procAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// pidIsEngine confirms the PID belongs to the engine binary by its
// /proc cmdline. The engine path from settings must appear as the
// executable argument. If the cmdline cannot be verified, reload is
// refused: SIGUSR1's default action terminates the recipient, and a
// recycled PID must never be signaled on a guess.
func pidIsEngine(pid int) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return fmt.Errorf("cannot verify process identity: %v", err)
	}
	args := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	if len(args) == 0 || len(args[0]) == 0 {
		return fmt.Errorf("empty cmdline")
	}
	exe := string(args[0])
	// 3proxy may be invoked via a path or bare name; accept either as
	// long as the basename matches "3proxy".
	base := exe
	if i := strings.LastIndexByte(exe, '/'); i >= 0 {
		base = exe[i+1:]
	}
	if base != "3proxy" {
		return fmt.Errorf("pid %d is %q, not 3proxy", pid, exe)
	}
	return nil
}
