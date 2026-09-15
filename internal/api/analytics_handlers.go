package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// requireAnalytics gates the analytics routes behind a wired analytics
// service. The nil case only occurs in builds that run the API without the
// pipeline; a 503 (not a silent 404) tells the operator the deployment is
// missing a component rather than the route being wrong.
func (s *Server) requireAnalytics(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.analytics == nil {
			writeError(w, r, http.StatusServiceUnavailable, "ANALYTICS_DISABLED",
				"analytics is not running in this deployment")
			return
		}
		next(w, r)
	}
}

// analyticsWeeks caps the traffic-history window. The dashboard asks for
// the recent past; anything beyond is a batch/reporting concern, not a
// live API one.
const (
	maxTrafficDays      = 366
	defaultTrafficDays  = 30
	maxDestinations     = 100
	defaultDestinations = 20
	maxRecentLive       = 500
	defaultRecentLive   = 50
)

// usagePeriodResponse is the API shape of one aggregated usage window.
type usagePeriodResponse struct {
	PeriodStart time.Time `json:"period_start"`
	Granularity string    `json:"granularity"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	Connections int64     `json:"connections"`
}

func toUsagePeriods(periods []store.UsagePeriod) []usagePeriodResponse {
	out := make([]usagePeriodResponse, 0, len(periods))
	for _, p := range periods {
		out = append(out, usagePeriodResponse{
			PeriodStart: p.PeriodStart,
			Granularity: p.Granularity,
			BytesIn:     p.BytesIn,
			BytesOut:    p.BytesOut,
			Connections: p.Connections,
		})
	}
	return out
}

// destinationResponse is the API shape of one aggregated destination.
// Host is destination metadata exactly as the client requested it —
// never decrypted content (THREAT-MODEL: destination stats).
type destinationResponse struct {
	Username string    `json:"username"`
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Protocol string    `json:"protocol"`
	Requests int64     `json:"requests"`
	Blocked  int64     `json:"blocked"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	LastSeen time.Time `json:"last_seen"`
}

func toDestinationResponse(d store.DestinationStat) destinationResponse {
	return destinationResponse{
		Username: d.Username,
		Host:     d.Host,
		Port:     d.Port,
		Protocol: d.Protocol,
		Requests: d.Requests,
		Blocked:  d.Blocked,
		BytesIn:  d.BytesIn,
		BytesOut: d.BytesOut,
		LastSeen: d.LastSeen,
	}
}

// connectionResponse is the API shape of one live connection record.
type connectionResponse struct {
	Time     string `json:"time"` // RFC3339
	Username string `json:"username"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	ClientIP string `json:"client_ip"`
	Blocked  bool   `json:"blocked"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// --- query parsing ---

// parseDays extracts the ?days= history window (default 30, max 366).
func parseDays(w http.ResponseWriter, r *http.Request) (int, bool) {
	days := defaultTrafficDays
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxTrafficDays {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST",
				"days must be 1-"+strconv.Itoa(maxTrafficDays))
			return 0, false
		}
		days = n
	}
	return days, true
}

// parseLimit extracts a bounded limit parameter with the given default.
func parseLimit(w http.ResponseWriter, r *http.Request, def, max int) (int, bool) {
	limit := def
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > max {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST",
				"limit must be 1-"+strconv.Itoa(max))
			return 0, false
		}
		limit = n
	}
	return limit, true
}

// sinceDayFrom converts a day count to the YYYY-MM-DD (UTC) lower bound
// the destination queries use.
func sinceDayFrom(days int) string {
	return time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
}

// sinceTimeFrom converts a day count to the timestamp lower bound the
// traffic-history queries use: midnight UTC of the first included day.
func sinceTimeFrom(days int) time.Time {
	now := time.Now().UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return midnight.AddDate(0, 0, -(days - 1))
}

// --- handlers ---

// handleAnalyticsTraffic answers the dashboard overview: global traffic
// history (day granularity) plus the live current-day counters and
// pipeline health.
func (s *Server) handleAnalyticsTraffic(w http.ResponseWriter, r *http.Request) {
	days, ok := parseDays(w, r)
	if !ok {
		return
	}
	history, err := s.analytics.GlobalTraffic(r.Context(), sinceTimeFrom(days))
	if err != nil {
		s.logger.Error("global traffic query failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"days":    days,
		"history": toUsagePeriods(history),
		"live":    s.analytics.Live(),
	})
}

// handleAnalyticsUser answers the user-detail view: one user's traffic
// history and top destinations.
func (s *Server) handleAnalyticsUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	days, ok := parseDays(w, r)
	if !ok {
		return
	}
	limit, ok := parseLimit(w, r, defaultDestinations, maxDestinations)
	if !ok {
		return
	}

	// 404 before querying: a traffic report for a nonexistent user is a
	// client error, not an empty result.
	if _, err := s.users.Get(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		} else {
			s.logger.Error("user lookup failed", "error", err.Error())
			writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		}
		return
	}

	history, err := s.analytics.UserTraffic(r.Context(), id, sinceTimeFrom(days))
	if err != nil {
		s.logger.Error("user traffic query failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	dests, err := s.analytics.UserDestinations(r.Context(), id, sinceDayFrom(days), limit)
	if err != nil {
		s.logger.Error("user destinations query failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	destOut := make([]destinationResponse, 0, len(dests))
	for _, d := range dests {
		destOut = append(destOut, toDestinationResponse(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":      id,
		"days":         days,
		"history":      toUsagePeriods(history),
		"destinations": destOut,
	})
}

// handleAnalyticsLive answers the live connections panel from the
// in-memory ring — no database involvement, so it stays fast (and
// answers) even while a flush is running. Optional ?username= filter.
func (s *Server) handleAnalyticsLive(w http.ResponseWriter, r *http.Request) {
	limit, ok := parseLimit(w, r, defaultRecentLive, maxRecentLive)
	if !ok {
		return
	}
	username := r.URL.Query().Get("username")
	recs := s.analytics.RecentConnections(limit, username)
	out := make([]connectionResponse, 0, len(recs))
	for _, rec := range recs {
		out = append(out, connectionResponse{
			Time:     time.UnixMilli(rec.UnixMillis).UTC().Format(time.RFC3339),
			Username: rec.Username,
			Protocol: rec.Protocol,
			Host:     rec.Host,
			Port:     rec.Port,
			ClientIP: rec.ClientIP,
			Blocked:  rec.Blocked,
			BytesIn:  rec.BytesIn,
			BytesOut: rec.BytesOut,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"connections": out,
		"live":        s.analytics.Live(),
	})
}

// handleAnalyticsDestinations answers the top-destinations panel, ordered
// by total bytes.
func (s *Server) handleAnalyticsDestinations(w http.ResponseWriter, r *http.Request) {
	days, ok := parseDays(w, r)
	if !ok {
		return
	}
	limit, ok := parseLimit(w, r, defaultDestinations, maxDestinations)
	if !ok {
		return
	}
	dests, err := s.analytics.TopDestinations(r.Context(), sinceDayFrom(days), limit)
	if err != nil {
		s.logger.Error("top destinations query failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	out := make([]destinationResponse, 0, len(dests))
	for _, d := range dests {
		out = append(out, toDestinationResponse(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"destinations": out})
}

// handleAnalyticsBlocked answers the blocked-destinations panel: where
// policy or quotas are refusing traffic, ordered by blocked count.
func (s *Server) handleAnalyticsBlocked(w http.ResponseWriter, r *http.Request) {
	days, ok := parseDays(w, r)
	if !ok {
		return
	}
	limit, ok := parseLimit(w, r, defaultDestinations, maxDestinations)
	if !ok {
		return
	}
	dests, err := s.analytics.BlockedDestinations(r.Context(), sinceDayFrom(days), limit)
	if err != nil {
		s.logger.Error("blocked destinations query failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	out := make([]destinationResponse, 0, len(dests))
	for _, d := range dests {
		out = append(out, toDestinationResponse(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"blocked": out})
}
