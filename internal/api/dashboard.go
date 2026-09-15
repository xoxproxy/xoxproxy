package api

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// dashboardFS holds the built SPA (web/ compiled via `make web`). The
// directory is committed build output: CI builds the binary from it
// without a node toolchain.
//
//go:embed all:static
var dashboardFS embed.FS

// spaCSP is the content security policy for the dashboard shell. The SPA
// bundles everything it needs (scripts, styles, fonts); nothing loads
// from third-party origins, and connect-src 'self' covers same-origin
// fetch and the SSE stream.
const spaCSP = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// mountDashboard registers the SPA's concrete routes:
//
//   - GET /           → the shell
//   - GET /assets/*   → hashed build artifacts, immutable caching
//
// Deep links (/users/42 and friends) are handled by spaRouter, not by a
// "GET /" catch-all: Go's mux resolves a GET catch-all above the
// automatic 405 a method-specific pattern would produce, so a catch-all
// would turn GET /api/v1/auth/logout into a 404 and break the
// no-GET-mutations guarantee the security tests assert.
//
// The shell itself is public — it is a static bundle with no data. Every
// piece of information flows through /api/v1/* behind withSession.
func (s *Server) mountDashboard(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.serveShell)
	assets, err := fs.Sub(dashboardFS, "static/assets")
	if err != nil {
		// Can only happen if the embed pattern and the directory
		// disagree; the build fails loudly before this ships.
		s.logger.Error("dashboard assets missing from build", "error", err.Error())
		return
	}
	files := http.StripPrefix("/assets/", http.FileServerFS(assets))
	mux.HandleFunc("GET /assets/", func(w http.ResponseWriter, r *http.Request) {
		// Vite emits content-hashed filenames: safe to cache forever.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Content-Security-Policy", spaCSP)
		files.ServeHTTP(w, r)
	})
}

// spaRouter wraps the mux with the client-side routing fallback: a GET
// for a path the mux does not own (anything but /, /assets/*, /api/*,
// /health/*) is an SPA deep link and renders the shell. All other
// requests pass through untouched, so API 404/405 semantics are exactly
// the mux's.
func (s *Server) spaRouter(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if r.Method == http.MethodGet &&
			p != "/" &&
			!strings.HasPrefix(p, "/api/") &&
			!strings.HasPrefix(p, "/health/") &&
			!strings.HasPrefix(p, "/assets/") {
			s.serveShell(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// serveShell returns index.html for the app shell. The SPA owns routing
// from there.
func (s *Server) serveShell(w http.ResponseWriter, r *http.Request) {
	data, err := dashboardFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "dashboard not built into this binary", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Security-Policy", spaCSP)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
