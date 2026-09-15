package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/analytics"
)

// streamTickInterval is the SSE cadence. Two seconds matches the
// dashboard's live-panel need (connections, bandwidth, health) without
// approaching the API's per-IP rate limit — the stream is one connection,
// not requests, so the limiter never sees it.
const streamTickInterval = 2 * time.Second

// streamEvent is one SSE `tick`. Small by design: live counters and
// health only, never per-connection data (GUIDE: no high-cardinality
// streaming).
type streamEvent struct {
	Analytics analytics.LiveSnapshot `json:"analytics"`
	// Resources, when a system provider is wired: the Overview tiles
	// refresh from the same stream instead of polling.
	CPUPercent float64 `json:"cpu_percent,omitempty"`
	RAMUsed    uint64  `json:"ram_used,omitempty"`
	RAMTotal   uint64  `json:"ram_total,omitempty"`
}

// handleAnalyticsStream serves GET /api/v1/analytics/stream as
// Server-Sent Events: one `tick` per interval until the client goes
// away. GET means no CSRF token is required (the withSession wrapper
// only enforces CSRF on state-changing methods); EventSource sends the
// session cookie same-origin.
func (s *Server) handleAnalyticsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "streaming unsupported")
		return
	}

	h := w.Header()
	// The API-wide middleware sets Cache-Control: no-store and a
	// default-src 'none' CSP; both are fine for SSE. Proxy-chain buffers
	// are disabled so each tick arrives immediately.
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Prime the connection with one immediate event so the dashboard
	// renders before the first tick.
	if s.writeStreamEvent(w, flusher, r.Context()) {
		return
	}

	ticker := time.NewTicker(streamTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if s.writeStreamEvent(w, flusher, r.Context()) {
				return
			}
		}
	}
}

// writeStreamEvent emits one tick; it returns true when the connection
// is gone (client disconnect surfaces as a write error). ctx comes from
// the original request; the Resources call is bounded internally.
func (s *Server) writeStreamEvent(w http.ResponseWriter, flusher http.Flusher, ctx context.Context) bool {
	ev := streamEvent{Analytics: s.analytics.Live()}
	if s.system != nil {
		if res, err := s.system.Resources(ctx); err == nil {
			ev.CPUPercent = res.CPUPercent
			ev.RAMUsed = res.MemUsed
			ev.RAMTotal = res.MemTotal
		}
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return true
	}
	if _, err := w.Write(append(append([]byte("event: tick\ndata: "), payload...), '\n', '\n')); err != nil {
		return true
	}
	flusher.Flush()
	return false
}
