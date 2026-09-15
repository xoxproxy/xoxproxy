// Package engine defines the desired-state contract between the control
// plane and the proxy data plane. The control plane renders this state
// into an engine-specific configuration and deploys it atomically; the
// data plane never reads from the database or the API (see
// docs/ARCHITECTURE.md, plane separation).
package engine

import (
	"fmt"
	"strings"
)

// Period is a quota reset period. The reset is enforced by the engine
// (3proxy counter semantics; see docs/SPIKE-3PROXY.md §2.5 for the
// boundary-skew caveat) while the control plane keeps its own ledger
// with exact UTC boundaries as the source of truth for display.
type Period string

const (
	PeriodDaily   Period = "daily"
	PeriodWeekly  Period = "weekly"
	PeriodMonthly Period = "monthly"
)

// Direction selects which traffic a quota counts.
type Direction string

const (
	DirIn  Direction = "in"  // downloads: bytes received from the target
	DirOut Direction = "out" // uploads: bytes sent to the target
	DirAll Direction = "all" // both directions combined
)

// Quota is a per-user traffic allowance. LimitBytes is an integer byte
// count (never floating point); the engine enforces it in whole
// megabytes, so the rendered allowance is LimitBytes rounded down —
// a rendered quota can never exceed the configured one.
type Quota struct {
	Period     Period
	LimitBytes int64
	Direction  Direction
}

// MiB is the enforcement granularity of the engine's native counters.
const MiB int64 = 1024 * 1024

// Protocol names a proxy protocol an account may use.
type Protocol string

const (
	ProtoHTTP   Protocol = "http"   // HTTP proxy + HTTPS CONNECT
	ProtoSOCKS5 Protocol = "socks5" // SOCKS5 proxy
)

// User is the data-plane view of a proxy user. EngineHash is the
// provider-specific password verifier (e.g. a 3proxy CR hash); the
// control plane's argon2id hash never crosses into the engine, and the
// plaintext password exists only at creation/reset time.
type User struct {
	Username     string
	EngineHash   string
	RecordNumber int64 // stable counter-file record id (never 0, never reused)

	// Protocols are the services the account may authenticate against.
	// Empty means no access at all (fail closed).
	Protocols []Protocol

	// DownloadBPS/UploadBPS are instantaneous bandwidth caps in bits per
	// second (3proxy bandlim semantics). Zero means unlimited.
	DownloadBPS int64
	UploadBPS   int64

	Quota *Quota // nil = unlimited
}

// State is the mutable desired state of the data plane: the accounts
// the control plane owns. Deployment-fixed parameters (paths, ports,
// connection caps) belong to the provider's Settings, not here.
type State struct {
	Users []User
}

// Validate checks the state for anything that cannot be rendered
// safely. It is the injection defense: every field that reaches an
// engine config file is validated here or by the provider, so hostile
// values are rejected before rendering regardless of what any UI
// allowed. An empty user list is valid (auth still denies everything —
// never an open proxy).
func (s State) Validate() error {
	var errs []error

	seenNames := make(map[string]bool, len(s.Users))
	seenRecords := make(map[int64]bool, len(s.Users))
	for i, u := range s.Users {
		if err := ValidateUsername(u.Username); err != nil {
			errs = append(errs, fmt.Errorf("user[%d]: %w", i, err))
		} else if seenNames[u.Username] {
			errs = append(errs, fmt.Errorf("user %q appears more than once", u.Username))
		}
		seenNames[u.Username] = true

		if u.RecordNumber < 1 {
			errs = append(errs, fmt.Errorf("user %q: record_number %d must be >= 1 (0 would drop quota persistence on reload)", u.Username, u.RecordNumber))
		} else if seenRecords[u.RecordNumber] {
			errs = append(errs, fmt.Errorf("record number %d used by more than one user (would corrupt the counter file)", u.RecordNumber))
		}
		seenRecords[u.RecordNumber] = true

		if u.DownloadBPS < 0 || u.UploadBPS < 0 {
			errs = append(errs, fmt.Errorf("user %q: bandwidth limits must be >= 0", u.Username))
		}
		seenProto := make(map[Protocol]bool, len(u.Protocols))
		for _, p := range u.Protocols {
			switch p {
			case ProtoHTTP, ProtoSOCKS5:
			default:
				errs = append(errs, fmt.Errorf("user %q: unknown protocol %q", u.Username, p))
			}
			if seenProto[p] {
				errs = append(errs, fmt.Errorf("user %q: protocol %q listed more than once", u.Username, p))
			}
			seenProto[p] = true
		}
		if u.Quota != nil {
			switch u.Quota.Period {
			case PeriodDaily, PeriodWeekly, PeriodMonthly:
			default:
				errs = append(errs, fmt.Errorf("user %q: quota period %q must be daily, weekly or monthly", u.Username, u.Quota.Period))
			}
			switch u.Quota.Direction {
			case DirIn, DirOut, DirAll:
			default:
				errs = append(errs, fmt.Errorf("user %q: quota direction %q must be in, out or all", u.Username, u.Quota.Direction))
			}
			if u.Quota.LimitBytes < MiB {
				errs = append(errs, fmt.Errorf("user %q: quota limit %d bytes is below the 1 MiB enforcement granularity", u.Username, u.Quota.LimitBytes))
			}
		}
	}

	if len(errs) == 1 {
		return errs[0]
	}
	if len(errs) > 1 {
		return fmt.Errorf("invalid engine state:\n  %s", strings.Join(errStrings(errs), "\n  "))
	}
	return nil
}

func errStrings(errs []error) []string {
	out := make([]string, len(errs))
	for i, e := range errs {
		out[i] = e.Error()
	}
	return out
}

// usernameCharset is deliberately strict. Usernames are embedded in
// engine configuration where whitespace, ':' and '"' would break token
// parsing (and ':' or a newline could inject new directives — the
// engine-side equivalent of command injection). Machine-generated names
// and all human-entered names pass through ValidateUsername before they
// ever reach a config file.
const usernameMaxLen = 64

// ValidateUsername enforces the username policy for proxy users. A
// username must start with an alphanumeric and may contain only
// alphanumerics, '.', '_' and '-'.
func ValidateUsername(name string) error {
	if name == "" {
		return fmt.Errorf("username is empty")
	}
	if len(name) > usernameMaxLen {
		return fmt.Errorf("username %q longer than %d characters", name, usernameMaxLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
			if i == 0 {
				return fmt.Errorf("username %q must start with a letter or digit", name)
			}
		default:
			return fmt.Errorf("username %q contains character %q outside [A-Za-z0-9._-]", name, string(rune(c)))
		}
	}
	return nil
}
