package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// render logs a record through a real JSON handler and returns the output.
func render(t *testing.T, level string, fn func(l *slog.Logger)) string {
	t.Helper()
	var buf bytes.Buffer
	l, err := New(&buf, level)
	if err != nil {
		t.Fatal(err)
	}
	fn(l)
	return buf.String()
}

func TestSecretIsRedactedEverywhere(t *testing.T) {
	const pass = "hunter2-super-secret"
	out := render(t, "info", func(l *slog.Logger) {
		l.Info("login attempt",
			"username", "alice",
			"password", Secret(pass),
		)
	})
	if strings.Contains(out, pass) {
		t.Fatalf("secret leaked into logs: %s", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Fatalf("expected redaction marker, got: %s", out)
	}
	// Structured fields must survive around the redaction.
	if !strings.Contains(out, `"username":"alice"`) {
		t.Fatalf("expected username field, got: %s", out)
	}
}

func TestSecretStringerRedacted(t *testing.T) {
	s := Secret("token-value")
	if got := s.String(); got != "[redacted]" {
		t.Fatalf("String() = %q", got)
	}
	if got := fmt.Sprintf("%s|%v", s, s); strings.Contains(got, "token-value") {
		t.Fatalf("fmt path leaked: %q", got)
	}
}

func TestRedactEmpty(t *testing.T) {
	if Redact("") != "" {
		t.Fatal("empty values should stay empty")
	}
	if Redact("x") != "[redacted]" {
		t.Fatal("non-empty values must redact")
	}
}

func TestJSONOutputShape(t *testing.T) {
	out := render(t, "info", func(l *slog.Logger) {
		l.Info("op", "key", "value")
	})
	var rec map[string]any
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("output is not one JSON object per line: %v\n%s", err, out)
	}
	if rec["service"] != "xoxproxy" {
		t.Fatalf("service field missing: %s", out)
	}
	if rec["level"] != "INFO" || rec["msg"] != "op" {
		t.Fatalf("missing standard fields: %s", out)
	}
}

func TestLevelFiltering(t *testing.T) {
	out := render(t, "warn", func(l *slog.Logger) {
		l.Info("should be filtered")
		l.Warn("should appear")
	})
	if strings.Contains(out, "should be filtered") {
		t.Fatalf("info leaked at warn level: %s", out)
	}
	if !strings.Contains(out, "should appear") {
		t.Fatalf("warn missing: %s", out)
	}
}

func TestParseLevel(t *testing.T) {
	for _, in := range []string{"debug", "info", "warn", "error", "INFO"} {
		if _, err := ParseLevel(in); err != nil {
			t.Errorf("ParseLevel(%q) = %v", in, err)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Error("unknown level must error")
	}
}

func TestNewRequestID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := NewRequestID()
		if !strings.HasPrefix(id, "req_") || len(id) != len("req_")+24 {
			t.Fatalf("malformed request id %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate request id %q", id)
		}
		seen[id] = true
	}
}
