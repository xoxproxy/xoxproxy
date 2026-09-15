//go:build windows

package threeproxy

import "fmt"

// The engine only ever runs on the Linux deployment host. These stubs
// keep the tree buildable (and deploy-atomicity testable) on Windows
// dev machines; the Linux CI build exercises the real paths.

func signalReload(pid int) error {
	return fmt.Errorf("3proxy reload signalling requires the Linux deployment host")
}

func procAlive(pid int) bool {
	return false
}

func pidIsEngine(pid int) error {
	return fmt.Errorf("engine process identity checks require /proc")
}
