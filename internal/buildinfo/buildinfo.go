// Package buildinfo carries version metadata injected at build time via
// -ldflags. It is the single source of truth for `xoxproxy version` output
// and the /api/v1/system endpoints.
package buildinfo

import "fmt"

// Populated by the Makefile / release pipeline:
//
//	-ldflags "-X github.com/xoxproxy/xoxproxy/internal/buildinfo.Version=$V ..."
var (
	Version   = "dev"
	GitCommit = "unknown"
	GoVersion = "unknown"
)

// String renders the one-line version banner.
func String() string {
	return fmt.Sprintf("xoxproxy %s (commit %s, go %s)", Version, GitCommit, GoVersion)
}
