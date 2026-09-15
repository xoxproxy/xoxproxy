// Package api hosts the HTTP control plane: routing, middleware, and the
// shared error envelope. Business logic lives in service packages; handlers
// here only translate HTTP to service calls.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/analytics"
	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/auth"
	"github.com/xoxproxy/xoxproxy/internal/deploy"
	"github.com/xoxproxy/xoxproxy/internal/store"
	"github.com/xoxproxy/xoxproxy/internal/system"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// HeaderRequestID is echoed on every response so clients can correlate
// errors with server logs.
const HeaderRequestID = "X-Request-ID"

// ctxKey is unexported to prevent context collisions with other packages.
type ctxKey int

const ctxKeyRequestID ctxKey = iota

// RequestID returns the request ID assigned by middleware, if present.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// ReadinessCheck is a named dependency probe. The control plane reports
// ready only when every check passes; the proxy engine is intentionally not
// among them — engine health has its own endpoint so an engine problem
// never takes the dashboard with it (ARCHITECTURE.md, failure boundaries).
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// Options configures the HTTP server.
type Options struct {
	// SecureCookies sets the Secure flag on session cookies. Enabled when
	// the dashboard is served over HTTPS (domain deployments); IP-only
	// HTTP deployments disable it explicitly and carry the documented
	// risk banner.
	SecureCookies bool
}

// AnalyticsService is the read-side surface of the analytics pipeline the
// API needs. The concrete *analytics.Service satisfies it; the interface
// exists so tests and the optional-analytics seam stay cheap.
type AnalyticsService interface {
	Live() analytics.LiveSnapshot
	RecentConnections(limit int, username string) []analytics.Record
	GlobalTraffic(ctx context.Context, since time.Time) ([]store.UsagePeriod, error)
	UserTraffic(ctx context.Context, userID int64, since time.Time) ([]store.UsagePeriod, error)
	UserDestinations(ctx context.Context, userID int64, sinceDay string, limit int) ([]store.DestinationStat, error)
	TopDestinations(ctx context.Context, sinceDay string, limit int) ([]store.DestinationStat, error)
	BlockedDestinations(ctx context.Context, sinceDay string, limit int) ([]store.DestinationStat, error)
}

// SystemProvider is the host-metrics surface the Server page needs. The
// concrete *system.Local satisfies it; a fake serves tests.
type SystemProvider interface {
	Identity(ctx context.Context) (system.Identity, error)
	Resources(ctx context.Context) (system.Resources, error)
}

// Server holds the HTTP control plane.
type Server struct {
	logger    *slog.Logger
	auth      *auth.Service
	audit     *audit.Service
	users     *users.Service
	deploy    *deploy.Service
	analytics AnalyticsService
	system    SystemProvider
	// trafficLogPath is the engine log the Logs page tails (read-only).
	trafficLogPath string
	// deployment carries the static posture the system status endpoint
	// reports (ports, TLS, public-IP source).
	deployment DeploymentInfo
	options   Options
	limiter   *rateLimiter

	readyMu sync.RWMutex
	ready   []ReadinessCheck
}

// NewServer builds the control-plane HTTP server. auth, audit, users, and
// deploy are the wired services; they are required (the API without
// authentication is not a supported deployment, and both user management
// and config deployment are core control-plane functions). analytics and
// sys may be nil in reduced deployments; their routes return 503 then.
func NewServer(logger *slog.Logger, authSvc *auth.Service, auditSvc *audit.Service, usersSvc *users.Service, deploySvc *deploy.Service, analyticsSvc AnalyticsService, sys SystemProvider, opts Options) *Server {
	return &Server{
		logger:    logger,
		auth:      authSvc,
		audit:     auditSvc,
		users:     usersSvc,
		deploy:    deploySvc,
		analytics: analyticsSvc,
		system:    sys,
		limiter:   newRateLimiter(rateLimitRate, rateLimitBurst),
	}
}

// SetTrafficLogPath configures the engine log the Logs page can tail.
// Called during boot after the engine settings are derived.
func (s *Server) SetTrafficLogPath(path string) { s.trafficLogPath = path }

// AddReadinessCheck registers a dependency probe for /health/ready.
// Checks are stable once the server starts serving; registration happens
// during boot before Listen.
func (s *Server) AddReadinessCheck(name string, check func(ctx context.Context) error) {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	s.ready = append(s.ready, ReadinessCheck{Name: name, Check: check})
}

// Handler returns the fully wired HTTP handler with middleware applied.
// Middleware order (outermost first): request ID → access log → security
// headers → rate limit → routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health: no authentication, no rate-limit exceptions — they are
	// cheap and must always answer.
	mux.HandleFunc("GET /health/live", s.handleLive)
	mux.HandleFunc("GET /health/ready", s.handleReady)

	// Authentication.
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.withSession(s.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/session", s.withSession(s.handleSessionInfo))
	mux.HandleFunc("POST /api/v1/auth/password", s.withSession(s.handlePasswordChange))

	// Audit trail.
	mux.HandleFunc("GET /api/v1/audit-logs", s.withSession(s.handleAuditList))

	// Proxy users.
	mux.HandleFunc("GET /api/v1/users", s.withSession(s.handleUserList))
	mux.HandleFunc("POST /api/v1/users", s.withSession(s.handleUserCreate))
	mux.HandleFunc("GET /api/v1/users/{id}", s.withSession(s.handleUserGet))
	mux.HandleFunc("PATCH /api/v1/users/{id}", s.withSession(s.handleUserUpdate))
	mux.HandleFunc("DELETE /api/v1/users/{id}", s.withSession(s.handleUserDelete))
	mux.HandleFunc("POST /api/v1/users/{id}/rotate-credentials", s.withSession(s.handleUserRotate))
	mux.HandleFunc("POST /api/v1/users/{id}/disable", s.withSession(s.handleUserDisable))
	mux.HandleFunc("POST /api/v1/users/{id}/enable", s.withSession(s.handleUserEnable))
	mux.HandleFunc("POST /api/v1/users/{id}/reset-quota", s.withSession(s.handleUserResetQuota))

	// Deploy pipeline: history, engine status, manual redeploy. Mutations
	// from user management redeploy automatically; the manual trigger is
	// for operator reconcile.
	mux.HandleFunc("GET /api/v1/config-versions", s.withSession(s.handleConfigVersionList))
	mux.HandleFunc("GET /api/v1/engine/status", s.withSession(s.handleEngineStatus))
	mux.HandleFunc("POST /api/v1/deploy", s.withSession(s.handleDeployTrigger))

	// Analytics: traffic history, per-user reports, live connections,
	// destination panels. All read-only, all authenticated.
	mux.HandleFunc("GET /api/v1/analytics/traffic", s.withSession(s.requireAnalytics(s.handleAnalyticsTraffic)))
	mux.HandleFunc("GET /api/v1/analytics/users/{id}", s.withSession(s.requireAnalytics(s.handleAnalyticsUser)))
	mux.HandleFunc("GET /api/v1/analytics/live", s.withSession(s.requireAnalytics(s.handleAnalyticsLive)))
	mux.HandleFunc("GET /api/v1/analytics/destinations", s.withSession(s.requireAnalytics(s.handleAnalyticsDestinations)))
	mux.HandleFunc("GET /api/v1/analytics/blocked", s.withSession(s.requireAnalytics(s.handleAnalyticsBlocked)))
	mux.HandleFunc("GET /api/v1/analytics/stream", s.withSession(s.requireAnalytics(s.handleAnalyticsStream)))

	// System: host identity and utilization for the Server/Overview
	// pages. Read-only observation; never part of readiness.
	mux.HandleFunc("GET /api/v1/system/status", s.withSession(s.requireSystem(s.handleSystemStatus)))
	mux.HandleFunc("GET /api/v1/system/resources", s.withSession(s.requireSystem(s.handleSystemResources)))

	// Logs: audit trail (paginated) and the engine traffic log tail.
	mux.HandleFunc("GET /api/v1/logs/engine", s.withSession(s.handleEngineLogTail))

	// Dashboard SPA (Phase 8): embedded static assets. Public shell; all
	// data stays behind withSession.
	s.mountDashboard(mux)

	// spaRouter adds the client-side routing fallback around the mux
	// (deep links render the shell) without disturbing API 404/405
	// semantics.
	var h http.Handler = s.spaRouter(mux)
	h = s.withRateLimit(h)
	h = s.withSecurityHeaders(h)
	h = s.withAccessLog(h)
	h = s.withRequestID(h)
	return h
}

// --- handlers ---

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	// Liveness is unconditional: if this handler can answer, the process
	// is serving. Never couple liveness to dependencies, or a DB blip
	// gets the process killed.
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	s.readyMu.RLock()
	checks := s.ready
	s.readyMu.RUnlock()

	var failed []string
	for _, c := range checks {
		if err := c.Check(r.Context()); err != nil {
			failed = append(failed, c.Name)
			s.logger.Warn("readiness check failed",
				slog.String("check", c.Name),
				slog.String("error", err.Error()),
			)
		}
	}
	if len(failed) > 0 {
		writeError(w, r, http.StatusServiceUnavailable, "NOT_READY",
			"service not ready: "+joinNames(failed))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"checks": checkNames(checks),
	})
}

func checkNames(checks []ReadinessCheck) []string {
	names := make([]string, len(checks))
	for i, c := range checks {
		names[i] = c.Name
	}
	return names
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}

// --- response helpers ---

// writeJSON emits a JSON body with the content type set. It never logs
// payloads (bodies may contain credentials) and swallows write errors the
// way net/http expects of terminal helpers.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// errorEnvelope is the single error shape for the whole API. Internal
// details never appear here — request_id links to server logs instead.
type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id,omitempty"`
	} `json:"error"`
}

// writeError emits the standard error envelope.
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	var env errorEnvelope
	env.Error.Code = code
	env.Error.Message = message
	env.Error.RequestID = RequestID(r.Context())
	writeJSON(w, status, env)
}
