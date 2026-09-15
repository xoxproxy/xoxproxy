package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// Limits for the HTTP surface. Bodies are small JSON documents; anything
// larger is hostile, not legitimate.
const (
	maxBodyBytes    = 1 << 20 // 1 MiB: JSON envelopes are a few hundred bytes
	rateLimitRate   = 5       // sustained requests/sec per IP
	rateLimitBurst  = 30
	rateLimitMaxIPs = 8192
)

// sessionCookie is the HttpOnly session cookie name.
const sessionCookie = "xox_session"

// ctxKeySession carries the authenticated session through handlers.
type ctxKeySession struct{}

// currentSession returns the authenticated session, or the zero value if
// the handler was not wrapped in withSession.
func currentSession(r *http.Request) store.AdminSession {
	if v, ok := r.Context().Value(ctxKeySession{}).(*sessionCtx); ok {
		return v.Session
	}
	return store.AdminSession{}
}

// currentAccount returns the authenticated account for the request.
func currentAccount(r *http.Request) store.AdminAccount {
	if v, ok := r.Context().Value(ctxKeySession{}).(*sessionCtx); ok {
		return v.Account
	}
	return store.AdminAccount{}
}

type sessionCtx struct {
	Session store.AdminSession
	Account store.AdminAccount
}

// --- security headers ---

// withSecurityHeaders applies the baseline response hardening. The API
// serves JSON only; when the dashboard lands (Phase 8) its asset routes
// get a CSP appropriate to a bundled SPA.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// --- per-IP rate limiting ---

// rateLimiter is an in-memory token bucket per client IP. It fails open
// past the tracking bound: the dashboard must stay available under
// address-spoofing pressure, and the security-critical throttling (login)
// lives in the auth service with its own state. It exists to shed load,
// not to be a security boundary.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst int) *rateLimiter {
	return &rateLimiter{buckets: map[string]*bucket{}, rate: float64(rate), burst: float64(burst)}
}

func (rl *rateLimiter) allow(ip string, now time.Time) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.buckets) >= rateLimitMaxIPs {
		// Drop idle buckets rather than refuse service.
		for k, b := range rl.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(rl.buckets, k)
			}
		}
	}
	b := rl.buckets[ip]
	if b == nil {
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / rl.rate * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		ok, retry := s.limiter.allow(ip, time.Now())
		if !ok {
			secs := int(retry.Seconds()) + 1
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
			writeError(w, r, http.StatusTooManyRequests, "RATE_LIMITED",
				"too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP resolves the originating IP. X-Forwarded-For is trusted only
// when the direct peer is loopback — in deployment that peer is Caddy on
// the same host. A remote client sending XFF directly to the API is not
// trusted, which keeps the login throttling unspoofable.
func clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// First entry = original client per the de-facto standard.
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	return host
}

// --- request bodies ---

// readJSON decodes a bounded JSON request body with strict content type.
// Cross-site forms cannot produce application/json bodies without a CORS
// preflight, which the API never approves — this check is therefore also a
// CSRF defense layer.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if ct := r.Header.Get("Content-Type"); ct != "" {
			if mediaType(ct) != "application/json" {
				writeError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE",
					"content type must be application/json")
				return false
			}
		} else {
			writeError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE",
				"content type must be application/json")
			return false
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxErr):
			writeError(w, r, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE",
				"request body exceeds limit")
		default:
			writeError(w, r, http.StatusBadRequest, "INVALID_JSON",
				"request body is not valid JSON for this endpoint")
		}
		return false
	}
	return true
}

func mediaType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(strings.ToLower(ct))
}

// --- session authentication + CSRF ---

// withSession authenticates the request via the session cookie and enforces
// the CSRF token on state-changing methods. The CSRF token is
// server-stored per session and compared in constant time; the SPA obtains
// it from the login or session endpoint.
func (s *Server) withSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			writeError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED",
				"authentication required")
			return
		}
		session, account, err := s.auth.ValidateSession(r.Context(), cookie.Value)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED",
				"session invalid or expired")
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			got := r.Header.Get("X-CSRF-Token")
			if got == "" || !constantTimeEqual(got, session.CSRFToken) {
				s.logger.Warn("csrf token mismatch",
					slog.String("request_id", RequestID(r.Context())),
					slog.String("path", r.URL.Path),
				)
				writeError(w, r, http.StatusForbidden, "CSRF_TOKEN_INVALID",
					"missing or invalid CSRF token")
				return
			}
		}

		ctx := context.WithValue(r.Context(), ctxKeySession{}, &sessionCtx{
			Session: session,
			Account: account,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// constantTimeEqual compares two strings without early exit.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
