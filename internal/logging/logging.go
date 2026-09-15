// Package logging provides the application logger and the utilities that
// keep logs safe: request-ID generation and credential redaction.
//
// Rules enforced by this package:
//   - all output is structured JSON (one object per line) for journald/log
//     shipping compatibility;
//   - values wrapped in Secret can never be rendered, even if passed to a
//     logger by mistake (see THREAT-MODEL.md, Information disclosure).
package logging

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// New returns the application logger writing JSON to w at the given level
// ("debug", "info", "warn", "error"). The service field identifies the
// control plane unambiguously in aggregated logs.
func New(w io.Writer, level string) (*slog.Logger, error) {
	lvl, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: lvl,
		// Keep source locations at debug only: production noise control.
		AddSource: lvl <= slog.LevelDebug,
	})
	return slog.New(h).With(slog.String("service", "xoxproxy")), nil
}

// Default returns the standard production logger (JSON to stdout). It is the
// one place that decides where process logs go; systemd captures stdout.
func Default(level string) (*slog.Logger, error) {
	return New(os.Stdout, level)
}

// ParseLevel converts a config level string to a slog level.
func ParseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: unknown level %q", level)
	}
}

// Secret wraps a credential so it cannot be rendered by slog. Passing a
// Secret to any log call produces "[redacted]" regardless of its contents.
//
// This is defense in depth, not the primary control: the primary rule is
// that credentials are never passed to loggers at all.
type Secret string

// LogValue implements slog.LogValuer and discards the underlying value.
func (Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// String implements fmt.Stringer with the same guarantee for %v/%s paths.
func (Secret) String() string { return "[redacted]" }

// Redact returns "[redacted]" for any non-empty value and "" for empty —
// a convenience for optional fields where emptiness is not sensitive.
func Redact(s string) string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}

// NewRequestID returns a random, non-guessable request identifier
// (96 bits from crypto/rand). It is safe for correlation in public error
// responses: it carries no information about the request.
func NewRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the system entropy source is broken;
		// correlation IDs degrade rather than the process.
		return "req_unavailable"
	}
	return "req_" + hex.EncodeToString(b[:])
}
