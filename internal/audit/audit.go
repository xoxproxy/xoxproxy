// Package audit provides the audit-trail service used by every privileged
// action. Audit failures are logged loudly but must never take down the
// operation being audited — with one exception pattern: handlers that
// receive an explicit error from Record decide themselves whether to
// proceed (see api handlers).
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// maxFieldLen bounds text fields to keep the audit table healthy against
// pathological callers.
const maxFieldLen = 256

// Service records audit entries.
type Service struct {
	repo   store.AuditRepository
	logger *slog.Logger
}

func New(logger *slog.Logger, repo store.AuditRepository) *Service {
	return &Service{repo: repo, logger: logger}
}

// Record validates, normalizes, and persists one entry. The entry gets a
// timestamp if the caller did not set one; times are always UTC.
func (s *Service) Record(ctx context.Context, e store.AuditEntry) error {
	if e.Action == "" {
		return fmt.Errorf("audit: action is required")
	}
	if e.Actor == "" {
		e.Actor = "unknown"
	}
	e.Actor = truncate(e.Actor)
	e.Action = truncate(e.Action)
	e.Target = truncate(e.Target)
	e.Result = truncate(e.Result)
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if err := s.repo.Record(ctx, e); err != nil {
		// Loud, structured, non-fatal: the caller's business decision
		// about failing the audited action stays with the caller.
		s.logger.Error("audit record failed",
			slog.String("action", e.Action),
			slog.String("error", err.Error()),
		)
		return err
	}
	return nil
}

// List queries audit entries (newest first).
func (s *Service) List(ctx context.Context, f store.AuditFilter) ([]store.AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 100
	}
	return s.repo.List(ctx, f)
}

func truncate(s string) string {
	if len(s) <= maxFieldLen {
		return s
	}
	return s[:maxFieldLen]
}
