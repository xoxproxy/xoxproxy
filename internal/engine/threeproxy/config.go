package threeproxy

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xoxproxy/xoxproxy/internal/buildinfo"
	"github.com/xoxproxy/xoxproxy/internal/engine"
)

// Settings holds the engine deployment paths and service parameters.
// Paths are validated as absolute POSIX paths even on Windows dev
// machines: the engine only ever runs on the Linux deployment host.
type Settings struct {
	ConfigFile  string // 3proxy.cfg equivalent; the reload target
	PidFile     string // written by 3proxy; source of the SIGUSR1 target
	CounterFile string // binary 3CF traffic-counter file
	LogFile     string // traffic log (parsed for accounting)

	HTTPPort   int
	SOCKS5Port int
	MaxConns   int // 0 = engine default
	Rotate     int // archived log files to keep; 0 = engine default

	// Nameservers are emitted as nserver directives with a name cache.
	// Empty falls back to the system resolver (correct but slower and
	// serialized); the installer populates this from resolv.conf.
	Nameservers []string

	// SetUID/SetGID drop privileges after binding (installer runs the
	// engine as root only if needed). Empty = omit.
	SetUID string
	SetGID string
}

// DefaultNameserverCacheSize matches 3proxy's recommended cache sizing
// for small resolvers.
const nscacheSize = 65535

// LogFormat is the record layout the control plane's accounting
// ingestion parses (logparse.go). Any change here is coupled to the
// parser and to docs/SPIKE-3PROXY.md §5.
//
//	G = GMT timestamps, %t.%.<millis> unix time, %N.%p service.port,
//	%E error code (10 = quota exceeded), %U username, %C:%c client,
//	%R:%r target, %O bytes to target (upload), %I bytes from target
//	(download), %h hops, %T request text last (free-form).
const LogFormat = "G%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"

// engineHashRe is the exact shape of verifiers this provider renders.
// Anything else is rejected before rendering — a hostile EngineHash
// (quotes, colons, newlines) must never reach the config file, where it
// would be config injection.
var engineHashRe = regexp.MustCompile(`^\$3\$[A-Za-z0-9]{1,64}\$[./0-9A-Za-z]{22}$`)

// Validate checks the settings for renderability.
func (s Settings) Validate() error {
	var errs []error
	for name, p := range map[string]string{
		"config_file":  s.ConfigFile,
		"pid_file":     s.PidFile,
		"counter_file": s.CounterFile,
		"log_file":     s.LogFile,
	} {
		// The engine runs on Linux, so paths are POSIX paths in
		// production; host-absolute paths are also accepted so the
		// deploy pipeline is testable on dev machines.
		if !path.IsAbs(p) && !filepath.IsAbs(p) {
			errs = append(errs, fmt.Errorf("settings %s %q must be an absolute path", name, p))
			continue
		}
		// Defense in depth: the control plane writes these paths, so a
		// traversal component or control byte can only be operator
		// error or a compromised config file — refuse to act on either.
		if hasTraversal(p) {
			errs = append(errs, fmt.Errorf("settings %s %q must not contain \"..\" path components", name, p))
		}
		for i := 0; i < len(p); i++ {
			if p[i] < 0x20 || p[i] == 0x7f {
				errs = append(errs, fmt.Errorf("settings %s %q contains control characters", name, p))
				break
			}
		}
	}
	if err := validatePort("http", s.HTTPPort); err != nil {
		errs = append(errs, err)
	}
	if err := validatePort("socks5", s.SOCKS5Port); err != nil {
		errs = append(errs, err)
	}
	if s.HTTPPort == s.SOCKS5Port {
		errs = append(errs, fmt.Errorf("http and socks5 ports must differ (both %d)", s.HTTPPort))
	}
	if s.MaxConns < 0 {
		errs = append(errs, fmt.Errorf("max_connections %d must be >= 0", s.MaxConns))
	}
	if s.Rotate < 0 {
		errs = append(errs, fmt.Errorf("rotate %d must be >= 0", s.Rotate))
	}
	for _, ns := range s.Nameservers {
		if !ipRe.MatchString(ns) {
			errs = append(errs, fmt.Errorf("nameserver %q is not an IP address", ns))
		}
	}
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return fmt.Errorf("invalid engine settings: %v", errs)
	}
}

var ipRe = regexp.MustCompile(`^[0-9a-fA-F:.]+$`)

func validatePort(name string, p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("%s port %d must be 1-65535", name, p)
	}
	return nil
}

// hasTraversal reports whether any path component is "..".
func hasTraversal(p string) bool {
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}

// periodLetters maps control-plane quota periods onto 3proxy counter
// reset types (man 3proxy.cfg: H/D/W/M).
var periodLetters = map[engine.Period]string{
	engine.PeriodDaily:   "D",
	engine.PeriodWeekly:  "W",
	engine.PeriodMonthly: "M",
}

// Render produces the complete 3proxy configuration for the desired
// state. Rendering is deterministic (users sorted by name) so
// unchanged state renders byte-identical config and deploys are
// idempotent. All inputs are re-validated here — rendering must be safe
// for crafted state values, not just for what the API produces.
//
// Layout notes (verified semantics, docs/SPIKE-3PROXY.md):
//   - `config` + `pidfile` make the reload target explicit.
//   - auth strong with an explicit allow list per service: users not in
//     the list are denied by the implicit trailing deny, and auth strong
//     refuses unknown users regardless — never an open proxy, even with
//     zero users.
//   - bandlim*/count* rules live in the global lists (flush only resets
//     the access ACL), so they are emitted once and apply to all
//     services.
//   - noforce is never emitted: reload must force re-authentication of
//     live connections so revoked users drop immediately.
func Render(state engine.State, st Settings) (string, error) {
	if err := st.Validate(); err != nil {
		return "", err
	}
	if err := state.Validate(); err != nil {
		return "", err
	}

	users := make([]engine.User, len(state.Users))
	copy(users, state.Users)
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })

	for _, u := range users {
		if !engineHashRe.MatchString(u.EngineHash) {
			return "", fmt.Errorf("user %q: engine hash is not a $3$ BLAKE2b-crypt verifier", u.Username)
		}
	}

	httpPort, socksPort := st.HTTPPort, st.SOCKS5Port

	var b strings.Builder
	b.WriteString("# Managed by xoxproxy — DO NOT EDIT.\n")
	b.WriteString("# Regenerated and deployed by the control plane; manual changes are lost.\n")
	fmt.Fprintf(&b, "# generated by %s\n", buildinfo.String())
	line(&b, "config", strconv.Quote(st.ConfigFile))
	line(&b, "pidfile", strconv.Quote(st.PidFile))
	if st.SetGID != "" {
		line(&b, "setgid", st.SetGID)
	}
	if st.SetUID != "" {
		line(&b, "setuid", st.SetUID)
	}
	for _, ns := range st.Nameservers {
		line(&b, "nserver", ns)
	}
	if len(st.Nameservers) > 0 {
		fmt.Fprintf(&b, "nscache %d\nnscache6 %d\n", nscacheSize, nscacheSize)
	}
	if st.MaxConns > 0 {
		fmt.Fprintf(&b, "maxconn %d\n", st.MaxConns)
	}
	line(&b, "log", strconv.Quote(st.LogFile)+" D")
	if st.Rotate > 0 {
		fmt.Fprintf(&b, "rotate %d\n", st.Rotate)
	}
	line(&b, "logformat", strconv.Quote(LogFormat))
	line(&b, "counter", strconv.Quote(st.CounterFile))

	// --- users (global password table) ---
	b.WriteString("\n# --- accounts ---\n")
	b.WriteString("auth strong\n")
	if len(users) > 0 {
		entries := make([]string, len(users))
		for i, u := range users {
			entries[i] = strconv.Quote(u.Username + ":CR:" + u.EngineHash)
		}
		// One users line per account: readable diffs, no line-length
		// surprises, and quoting keeps the $ from being read as an
		// include directive.
		for _, e := range entries {
			b.WriteString("users " + e + "\n")
		}
	}

	// --- per-user limits (bandwidth + quotas; global, survive flush) ---
	b.WriteString("\n# --- limits ---\n")
	for _, u := range users {
		if u.DownloadBPS > 0 {
			fmt.Fprintf(&b, "bandlimin %d %s\n", u.DownloadBPS, u.Username)
		}
		if u.UploadBPS > 0 {
			fmt.Fprintf(&b, "bandlimout %d %s\n", u.UploadBPS, u.Username)
		}
		if u.Quota != nil {
			directive := "count" + string(u.Quota.Direction)
			mb := u.Quota.LimitBytes / engine.MiB // floor: never exceed the configured limit
			fmt.Fprintf(&b, "%s %d %s %d %s\n",
				directive, u.RecordNumber, periodLetters[u.Quota.Period], mb, u.Username)
		}
	}

	// --- services (access ACL per service, filtered by protocol) ---
	renderService := func(name, directive string, port int, proto engine.Protocol) {
		fmt.Fprintf(&b, "\n# --- %s ---\n", name)
		b.WriteString("flush\n")
		for _, u := range users {
			if !hasProtocol(u, proto) {
				continue
			}
			b.WriteString("allow " + u.Username + "\n")
		}
		fmt.Fprintf(&b, "%s -p%d\n", directive, port)
	}
	renderService("HTTP proxy", "proxy", httpPort, engine.ProtoHTTP)
	renderService("SOCKS5 proxy", "socks", socksPort, engine.ProtoSOCKS5)

	return b.String(), nil
}

func line(b *strings.Builder, directive, value string) {
	fmt.Fprintf(b, "%s %s\n", directive, value)
}

// hasProtocol reports whether the account may use the service.
func hasProtocol(u engine.User, proto engine.Protocol) bool {
	for _, p := range u.Protocols {
		if p == proto {
			return true
		}
	}
	return false
}
