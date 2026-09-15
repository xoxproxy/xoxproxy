// Package config loads and validates the xoxproxy control-plane
// configuration. All configuration is desired state for the control plane
// only; the proxy data plane is configured exclusively through the deploy
// pipeline (see internal/engine and internal/deploy in later phases).
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"

	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Default file locations on a deployed host. Overridable with -config or
// $XOXPROXY_CONFIG for development and testing.
const (
	DefaultPath       = "/etc/xoxproxy/config.toml"
	EnvOverride       = "XOXPROXY_CONFIG"
	defaultListenAddr = "127.0.0.1:8080"
	defaultDBPath     = "/var/lib/xoxproxy/xoxproxy.db"
	defaultEngineCfg  = "/etc/xoxproxy/engine"
	defaultEngineBin  = "/usr/bin/3proxy"
	defaultFlushIntvl = 30 * time.Second
	defaultQueueSize  = 8192
	minEnginePort     = 1024 // engine runs as an unprivileged user
	maxAnalyticsQueue = 1 << 20
	// Monitoring bounds: everything the monitoring pipeline keeps in
	// memory is capped, so a 1-vCPU VPS cannot be exhausted by
	// analytics no matter how varied the traffic is.
	defaultRetentionDays    = 90
	defaultMaxDestinations  = 1000
	defaultRecentConnection = 500
	maxRetentionDays        = 3650
	maxDestinationsPerUser  = 10000
	maxRecentConnections    = 10000
)

// ProxyProviders lists the engine providers this build knows how to manage.
// "threeproxy" is the only provider in v1; the registry exists so adding a
// second provider does not change the config contract.
var ProxyProviders = []string{"threeproxy"}

type Config struct {
	Server    ServerConfig    `toml:"server"`
	Database  DatabaseConfig  `toml:"database"`
	Engine    EngineConfig    `toml:"engine"`
	Proxy     ProxyConfig     `toml:"proxy"`
	Analytics AnalyticsConfig `toml:"analytics"`
	Log       LogConfig       `toml:"log"`
}

// ServerConfig controls the HTTP control-plane listener. It is expected to
// sit behind Caddy (TLS) in production; binding loopback by default means a
// fresh install is never accidentally internet-exposed.
type ServerConfig struct {
	Listen string `toml:"listen"`
	// PublicBaseURL is the externally reachable dashboard origin
	// (e.g. "https://proxy.example.com"), used for link generation and
	// cookie scoping. Empty means "not configured" and disables absolute
	// link generation.
	PublicBaseURL string `toml:"public_base_url"`
}

type DatabaseConfig struct {
	Path string `toml:"path"`
}

type EngineConfig struct {
	Provider   string `toml:"provider"`
	BinaryPath string `toml:"binary_path"`
	ConfigDir  string `toml:"config_dir"`
}

type ProxyConfig struct {
	HTTPPort   int `toml:"http_port"`
	SOCKS5Port int `toml:"socks5_port"`
}

type AnalyticsConfig struct {
	// FlushInterval is a Go duration string (e.g. "30s") for the
	// analytics counter flush cadence.
	FlushInterval string `toml:"flush_interval"`
	// QueueSize bounds the analytics ingestion queue. When full,
	// counters are coalesced in memory rather than blocking traffic
	// accounting pipelines.
	QueueSize int `toml:"queue_size"`
	// Verbosity selects the monitoring detail level:
	//   "counters" — aggregate statistics only (lightest)
	//   "detailed" — counters + a bounded recent-connections ring
	//               (live view for the dashboard)
	Verbosity string `toml:"verbosity"`
	// RetentionDays bounds how long per-destination statistics are kept
	// in the database (0 = keep forever). Aggregate usage periods are
	// always kept — they are tiny and are the quota ledger.
	RetentionDays int `toml:"retention_days"`
	// MaxDestinationsPerUser caps the distinct (host, port, protocol)
	// destinations tracked per user in memory and on disk. Overflow
	// aggregates into a "(other)" bucket, so RAM is bounded no matter
	// how scattered the traffic is.
	MaxDestinationsPerUser int `toml:"max_destinations_per_user"`
	// RecentConnections is the size of the in-memory recent-connections
	// ring (verbosity "detailed"). Never persisted; 0 disables the ring.
	RecentConnections int `toml:"recent_connections"`
}

// Monitoring verbosity levels.
const (
	VerbosityCounters = "counters"
	VerbosityDetailed = "detailed"
)

type LogConfig struct {
	Level string `toml:"level"`
}

// Defaults returns the built-in configuration. Every deployment is expected
// to run with these unless an operator explicitly overrides them.
func Defaults() Config {
	return Config{
		Server: ServerConfig{
			Listen: defaultListenAddr,
		},
		Database: DatabaseConfig{Path: defaultDBPath},
		Engine: EngineConfig{
			Provider:   "threeproxy",
			BinaryPath: defaultEngineBin,
			ConfigDir:  defaultEngineCfg,
		},
		Proxy: ProxyConfig{HTTPPort: 3128, SOCKS5Port: 1080},
		Analytics: AnalyticsConfig{
			FlushInterval:          defaultFlushIntvl.String(),
			QueueSize:              defaultQueueSize,
			Verbosity:              VerbosityDetailed,
			RetentionDays:          defaultRetentionDays,
			MaxDestinationsPerUser: defaultMaxDestinations,
			RecentConnections:      defaultRecentConnection,
		},
		Log: LogConfig{Level: "info"},
	}
}

// Load reads the TOML file at path over the built-in defaults and validates
// the result. It returns a single error joining every validation failure so
// operators see the full picture, not one problem per run.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return Config{}, fmt.Errorf("config: no path given")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config: %s invalid: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the configuration for structural errors and unsafe values.
// It fails closed: anything ambiguous or unrenderable is an error.
func (c Config) Validate() error {
	var errs []error

	// --- server ---
	if !strings.Contains(c.Server.Listen, ":") {
		errs = append(errs, fmt.Errorf("server.listen %q must bind an explicit address (host:port), not a bare port", c.Server.Listen))
	} else if host, portStr, err := net.SplitHostPort(c.Server.Listen); err != nil {
		errs = append(errs, fmt.Errorf("server.listen %q is not host:port", c.Server.Listen))
	} else if host == "" {
		errs = append(errs, fmt.Errorf("server.listen must bind an explicit address, not bare port %q", c.Server.Listen))
	} else if p, err := parsePort(portStr); err != nil {
		errs = append(errs, fmt.Errorf("server.listen: %w", err))
	} else if p < 1 {
		errs = append(errs, fmt.Errorf("server.listen port must be >= 1"))
	}
	if c.Server.PublicBaseURL != "" {
		if u, err := url.Parse(c.Server.PublicBaseURL); err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" {
			errs = append(errs, fmt.Errorf("server.public_base_url %q must be an origin like https://proxy.example.com", c.Server.PublicBaseURL))
		}
	}

	// --- database ---
	if !isAbsPOSIX(c.Database.Path) {
		errs = append(errs, fmt.Errorf("database.path %q must be an absolute path", c.Database.Path))
	}

	// --- engine ---
	if !providerKnown(c.Engine.Provider) {
		errs = append(errs, fmt.Errorf("engine.provider %q is not one of %s", c.Engine.Provider, strings.Join(ProxyProviders, ", ")))
	}
	if !isAbsPOSIX(c.Engine.BinaryPath) {
		errs = append(errs, fmt.Errorf("engine.binary_path %q must be an absolute path", c.Engine.BinaryPath))
	}
	if !isAbsPOSIX(c.Engine.ConfigDir) {
		errs = append(errs, fmt.Errorf("engine.config_dir %q must be an absolute path", c.Engine.ConfigDir))
	}

	// --- proxy ports ---
	if err := validateEnginePort("proxy.http_port", c.Proxy.HTTPPort); err != nil {
		errs = append(errs, err)
	}
	if err := validateEnginePort("proxy.socks5_port", c.Proxy.SOCKS5Port); err != nil {
		errs = append(errs, err)
	}
	if c.Proxy.HTTPPort == c.Proxy.SOCKS5Port {
		errs = append(errs, fmt.Errorf("proxy.http_port and proxy.socks5_port must differ (both %d)", c.Proxy.HTTPPort))
	}

	// --- analytics ---
	if d, err := time.ParseDuration(c.Analytics.FlushInterval); err != nil {
		errs = append(errs, fmt.Errorf("analytics.flush_interval %q: %v", c.Analytics.FlushInterval, err))
	} else if d <= 0 || d > 10*time.Minute {
		errs = append(errs, fmt.Errorf("analytics.flush_interval %q must be > 0 and <= 10m", c.Analytics.FlushInterval))
	}
	if c.Analytics.QueueSize <= 0 || c.Analytics.QueueSize > maxAnalyticsQueue {
		errs = append(errs, fmt.Errorf("analytics.queue_size %d must be between 1 and %d", c.Analytics.QueueSize, maxAnalyticsQueue))
	}
	switch c.Analytics.Verbosity {
	case VerbosityCounters, VerbosityDetailed:
	default:
		errs = append(errs, fmt.Errorf("analytics.verbosity %q must be one of counters, detailed", c.Analytics.Verbosity))
	}
	if c.Analytics.RetentionDays < 0 || c.Analytics.RetentionDays > maxRetentionDays {
		errs = append(errs, fmt.Errorf("analytics.retention_days %d must be between 0 (keep forever) and %d", c.Analytics.RetentionDays, maxRetentionDays))
	}
	if n := c.Analytics.MaxDestinationsPerUser; n < 10 || n > maxDestinationsPerUser {
		errs = append(errs, fmt.Errorf("analytics.max_destinations_per_user %d must be between 10 and %d", n, maxDestinationsPerUser))
	}
	if n := c.Analytics.RecentConnections; n < 0 || n > maxRecentConnections {
		errs = append(errs, fmt.Errorf("analytics.recent_connections %d must be between 0 and %d", n, maxRecentConnections))
	}

	// --- log ---
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level %q must be one of debug, info, warn, error", c.Log.Level))
	}

	return errors.Join(errs...)
}

// AnalyticsFlush returns the parsed flush cadence. Only valid after
// Validate has passed.
func (c Config) AnalyticsFlush() (time.Duration, error) {
	return time.ParseDuration(c.Analytics.FlushInterval)
}

// LogFileMode is the permission applied to control-plane state files. It is
// defined here so every writer agrees; secrets get a stricter mode in their
// own package.
const LogFileMode fs.FileMode = 0o640

func validateEnginePort(name string, p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("%s %d must be 1-65535", name, p)
	}
	if p < minEnginePort {
		return fmt.Errorf("%s %d: the engine runs unprivileged and cannot bind ports < %d", name, p, minEnginePort)
	}
	return nil
}

func parsePort(s string) (int, error) {
	var p int
	if _, err := fmt.Sscanf(s, "%d", &p); err != nil {
		return 0, fmt.Errorf("port %q is not numeric", s)
	}
	return p, nil
}

func providerKnown(p string) bool {
	for _, known := range ProxyProviders {
		if p == known {
			return true
		}
	}
	return false
}

// isAbsPOSIX reports whether the path is absolute in POSIX terms. xoxproxy
// deploys only to Linux, so configuration paths are validated with POSIX
// semantics even when tests run on Windows dev machines — filepath.IsAbs
// would reject every correct production path there.
func isAbsPOSIX(p string) bool {
	return strings.HasPrefix(p, "/")
}
