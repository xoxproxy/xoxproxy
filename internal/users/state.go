package users

import (
	"time"

	"github.com/xoxproxy/xoxproxy/internal/engine"
	"github.com/xoxproxy/xoxproxy/internal/store"
)

// BuildEngineState derives the data-plane desired state from the persisted
// users. It is pure: the same rows always produce the same state, so the
// deployment pipeline (Phase 6) can render, diff, and deploy idempotently.
//
// Quota mapping: the engine enforces one counter per user, so when both a
// monthly and a daily quota are configured, the monthly one wins — it is
// the cost-protection bound; the daily figure remains stored for
// control-plane reporting (and per-period enforcement arrives with
// control-plane reconciliation in a later phase). This is a documented v1
// limitation (docs/DESIGN-REVIEW.md, quota semantics).
//
// RecordNumber is the user's database row id: stable across reloads (the
// counter file keys on it), never reused (AUTOINCREMENT), never 0.
func BuildEngineState(rows []store.EngineUser, now time.Time) engine.State {
	state := engine.State{Users: make([]engine.User, 0, len(rows))}
	for _, row := range rows {
		u := row.User
		// Defense in depth: the repository query already filters these,
		// but the builder must stay correct even for a hand-fed row set.
		if u.Status != store.UserActive {
			continue
		}
		if u.ExpiresAt != nil && !u.ExpiresAt.After(now) {
			continue
		}

		eu := engine.User{
			Username:     u.Username,
			EngineHash:   row.EngineHash,
			RecordNumber: u.ID,
			Protocols:    toEngineProtocols(u.AllowedProtocols),
			DownloadBPS:  u.DownloadBPS,
			UploadBPS:    u.UploadBPS,
		}
		if q := engineQuota(u); q != nil {
			eu.Quota = q
		}
		state.Users = append(state.Users, eu)
	}
	return state
}

func engineQuota(u store.ProxyUser) *engine.Quota {
	limit, period := int64(0), engine.Period("")
	switch {
	case u.QuotaBytesMonthly > 0:
		limit, period = u.QuotaBytesMonthly, engine.PeriodMonthly
	case u.QuotaBytesDaily > 0:
		limit, period = u.QuotaBytesDaily, engine.PeriodDaily
	default:
		return nil
	}
	return &engine.Quota{
		Period:     period,
		LimitBytes: limit,
		Direction:  engine.DirAll,
	}
}

func toEngineProtocols(ps []string) []engine.Protocol {
	out := make([]engine.Protocol, 0, len(ps))
	for _, p := range ps {
		// The vocabulary is validated at input; unknown values cannot be
		// persisted. Anything unexpected is skipped rather than rendered —
		// fail closed.
		switch engine.Protocol(p) {
		case engine.ProtoHTTP, engine.ProtoSOCKS5:
			out = append(out, engine.Protocol(p))
		}
	}
	return out
}
