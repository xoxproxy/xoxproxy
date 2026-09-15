package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// maxAuditPage bounds the audit list page size.
const maxAuditPage = 200

// auditListFilter translates validated query parameters into the store
// filter. Action values are matched exactly against the known action
// vocabulary, so no arbitrary SQL fragments travel through.
func auditListFilter(action string, beforeID int64, limit int) store.AuditFilter {
	return store.AuditFilter{Action: action, BeforeID: beforeID, Limit: limit}
}

type auditEntryResponse struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	RequestID string    `json:"request_id"`
	SourceIP  string    `json:"source_ip"`
	Result    string    `json:"result"`
	Detail    string    `json:"detail"`
}

// handleAuditList serves GET /api/v1/audit-logs with cursor pagination:
//
//	?limit=100       page size (<= 200)
//	?before_id=N     entries older than the given ID
//	?action=name     filter by action
func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxAuditPage {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST",
				"limit must be an integer between 1 and 200")
			return
		}
		limit = n
	}
	var beforeID int64
	if v := r.URL.Query().Get("before_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST",
				"before_id must be a positive integer")
			return
		}
		beforeID = n
	}
	action := r.URL.Query().Get("action")

	entries, err := s.audit.List(r.Context(), auditListFilter(action, beforeID, limit))
	if err != nil {
		s.logger.Error("audit list failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	out := make([]auditEntryResponse, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditEntryResponse{
			ID: e.ID, Timestamp: e.Timestamp, Actor: e.Actor, Action: e.Action,
			Target: e.Target, RequestID: e.RequestID, SourceIP: e.SourceIP,
			Result: e.Result, Detail: e.Detail,
		})
	}
	// next_before_id enables the next page without trusting wall-clock
	// cursors.
	resp := map[string]any{"entries": out}
	if len(out) == limit {
		resp["next_before_id"] = out[len(out)-1].ID
	}
	writeJSON(w, http.StatusOK, resp)
}
