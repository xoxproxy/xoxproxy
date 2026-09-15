package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/analytics"
	"github.com/xoxproxy/xoxproxy/internal/store"
)

// stubAnalytics is a canned AnalyticsService for handler tests: it serves
// fixed traffic history and destinations and a live ring with one record.
type stubAnalytics struct {
	live      analytics.LiveSnapshot
	recent    []analytics.Record
	periods   []store.UsagePeriod
	dests     []store.DestinationStat
	userDests map[int64][]store.DestinationStat
}

func (s *stubAnalytics) Live() analytics.LiveSnapshot { return s.live }
func (s *stubAnalytics) RecentConnections(limit int, username string) []analytics.Record {
	var out []analytics.Record
	for _, r := range s.recent {
		if username == "" || r.Username == username {
			out = append(out, r)
		}
	}
	return out
}
func (s *stubAnalytics) GlobalTraffic(ctx context.Context, since time.Time) ([]store.UsagePeriod, error) {
	return s.periods, nil
}
func (s *stubAnalytics) UserTraffic(ctx context.Context, userID int64, since time.Time) ([]store.UsagePeriod, error) {
	return s.periods, nil
}
func (s *stubAnalytics) UserDestinations(ctx context.Context, userID int64, sinceDay string, limit int) ([]store.DestinationStat, error) {
	return s.userDests[userID], nil
}
func (s *stubAnalytics) TopDestinations(ctx context.Context, sinceDay string, limit int) ([]store.DestinationStat, error) {
	return s.dests, nil
}
func (s *stubAnalytics) BlockedDestinations(ctx context.Context, sinceDay string, limit int) ([]store.DestinationStat, error) {
	return s.dests, nil
}

// newAnalyticsTestServer returns a logged-in server wired with the stub
// analytics service, plus the session cookie and CSRF token.
func newAnalyticsTestServer(t *testing.T, stub *stubAnalytics) (*Server, http.Handler, string, string) {
	t.Helper()
	srv, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	srv.analytics = stub
	h := srv.Handler()
	cookie, csrf := login(t, h)
	return srv, h, cookie, csrf
}

func TestAnalyticsRoutesRequireSession(t *testing.T) {
	stub := &stubAnalytics{}
	_, h, _, _ := newAnalyticsTestServer(t, stub)
	for _, path := range []string{
		"/api/v1/analytics/traffic",
		"/api/v1/analytics/users/1",
		"/api/v1/analytics/live",
		"/api/v1/analytics/destinations",
		"/api/v1/analytics/blocked",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s without session = %d, want 401", path, rec.Code)
		}
	}
}

func TestAnalyticsDisabledWhenServiceMissing(t *testing.T) {
	srv, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	srv.analytics = nil
	h := srv.Handler()
	cookie, _ := login(t, h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/traffic", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("analytics without service = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ANALYTICS_DISABLED") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestAnalyticsTrafficHandler(t *testing.T) {
	stub := &stubAnalytics{
		live: analytics.LiveSnapshot{Day: "2026-09-15", Requests: 5, Ingested: 5},
		periods: []store.UsagePeriod{{
			PeriodStart: time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC),
			Granularity: "day", BytesIn: 1000, BytesOut: 500, Connections: 4,
		}},
	}
	_, h, cookie, csrf := newAnalyticsTestServer(t, stub)

	req := authed(http.MethodGet, "/api/v1/analytics/traffic?days=7", cookie, csrf, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("traffic = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Days    int `json:"days"`
		History []struct {
			PeriodStart time.Time `json:"period_start"`
			BytesIn     int64     `json:"bytes_in"`
			Connections int64     `json:"connections"`
		} `json:"history"`
		Live struct {
			Day      string `json:"day"`
			Requests int64  `json:"requests"`
		} `json:"live"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Days != 7 || len(resp.History) != 1 || resp.History[0].BytesIn != 1000 {
		t.Fatalf("history response = %+v", resp)
	}
	if resp.Live.Day != "2026-09-15" || resp.Live.Requests != 5 {
		t.Fatalf("live response = %+v", resp.Live)
	}
}

func TestAnalyticsTrafficRejectsBadDays(t *testing.T) {
	stub := &stubAnalytics{}
	_, h, cookie, csrf := newAnalyticsTestServer(t, stub)
	for _, q := range []string{"days=0", "days=-1", "days=9999", "days=abc"} {
		req := authed(http.MethodGet, "/api/v1/analytics/traffic?"+q, cookie, csrf, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", q, rec.Code)
		}
	}
}

func TestAnalyticsUserHandler(t *testing.T) {
	// Create a real user through the API so the 404 path is exercised
	// against the real store.
	stub := &stubAnalytics{
		periods: []store.UsagePeriod{{
			PeriodStart: time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC),
			Granularity: "day", BytesIn: 100, Connections: 1,
		}},
	}
	_, h, cookie, csrf := newAnalyticsTestServer(t, stub)

	// Create user via the API.
	rec := httptest.NewRecorder()
	req := authed(http.MethodPost, "/api/v1/users", cookie, csrf,
		strings.NewReader(`{"username":"reportuser","allowed_protocols":["http"]}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	stub.userDests = map[int64][]store.DestinationStat{
		created.ID: {{Username: "reportuser", Host: "example.com", Port: 443, Protocol: "https", Requests: 3}},
	}

	// Per-user analytics.
	req = authed(http.MethodGet, "/api/v1/analytics/users/"+itoa(created.ID)+"?days=7&limit=5", cookie, csrf, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("user analytics = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		UserID  int64 `json:"user_id"`
		History []struct {
			Connections int64 `json:"connections"`
		} `json:"history"`
		Destinations []struct {
			Host string `json:"host"`
		} `json:"destinations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.UserID != created.ID || len(resp.History) != 1 || len(resp.Destinations) != 1 || resp.Destinations[0].Host != "example.com" {
		t.Fatalf("user analytics response = %+v", resp)
	}

	// Unknown user: 404, not empty.
	req = authed(http.MethodGet, "/api/v1/analytics/users/99999", cookie, csrf, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown user = %d, want 404", rec.Code)
	}

	// Malformed id: 400.
	req = authed(http.MethodGet, "/api/v1/analytics/users/abc", cookie, csrf, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id = %d, want 400", rec.Code)
	}
}

func TestAnalyticsLiveHandler(t *testing.T) {
	stub := &stubAnalytics{
		live: analytics.LiveSnapshot{Day: "2026-09-15", RingEnabled: true},
		recent: []analytics.Record{
			{UnixMillis: 2000, Username: "bob", Host: "b.com", Port: 443, Protocol: "https"},
			{UnixMillis: 1000, Username: "alice", Host: "a.com", Port: 80, Protocol: "http"},
		},
	}
	_, h, cookie, csrf := newAnalyticsTestServer(t, stub)

	req := authed(http.MethodGet, "/api/v1/analytics/live?username=alice", cookie, csrf, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("live = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Connections []struct {
			Username string `json:"username"`
			Host     string `json:"host"`
			Time     string `json:"time"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Connections) != 1 || resp.Connections[0].Username != "alice" {
		t.Fatalf("live connections = %+v", resp.Connections)
	}
	if resp.Connections[0].Time != "1970-01-01T00:00:01Z" {
		t.Fatalf("time format = %q", resp.Connections[0].Time)
	}
}

func TestAnalyticsDestinationsHandlers(t *testing.T) {
	stub := &stubAnalytics{
		dests: []store.DestinationStat{
			{Username: "alice", Host: "top.com", Port: 443, Protocol: "https", BytesIn: 500},
			{Username: "bob", Host: "blocked.net", Port: 80, Protocol: "http", Blocked: 7},
		},
	}
	_, h, cookie, csrf := newAnalyticsTestServer(t, stub)

	for _, tc := range []struct {
		path string
		key  string
	}{
		{"/api/v1/analytics/destinations?days=30&limit=10", "destinations"},
		{"/api/v1/analytics/blocked?days=30&limit=10", "blocked"},
	} {
		req := authed(http.MethodGet, tc.path, cookie, csrf, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", tc.path, rec.Code, rec.Body.String())
		}
		var resp map[string][]map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp[tc.key]) != 2 {
			t.Fatalf("%s returned %d rows: %s", tc.path, len(resp[tc.key]), rec.Body.String())
		}
	}
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [21]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
