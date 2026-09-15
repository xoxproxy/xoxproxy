package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/auth"
)

// Input bounds: usernames and passwords that exceed these lengths are
// rejected before any expensive hashing happens.
const (
	maxUsernameLen = 64
	maxPasswordLen = 256
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionResponse struct {
	Username  string    `json:"username"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// setSessionCookie writes the HttpOnly session cookie. The raw token never
// appears in a response body — only the cookie carries it.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.options.SecureCookies,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.options.SecureCookies,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Username) == 0 || len(req.Username) > maxUsernameLen ||
		len(req.Password) == 0 || len(req.Password) > maxPasswordLen {
		// Same response as bad credentials: no oracle about which part
		// was wrong.
		writeError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
		return
	}

	result, err := s.auth.Login(r.Context(), auth.LoginInput{
		Username:  req.Username,
		Password:  req.Password,
		SourceIP:  clientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: RequestID(r.Context()),
	})
	switch {
	case errors.Is(err, auth.ErrIPBlocked):
		w.Header().Set("Retry-After", "60")
		writeError(w, r, http.StatusTooManyRequests, "TOO_MANY_ATTEMPTS",
			"too many attempts, try again later")
	case errors.Is(err, auth.ErrInvalidCredentials):
		// Identical body for unknown user, wrong password, and locked
		// account (see auth.Service.Login).
		writeError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
	case err != nil:
		s.logger.Error("login failed unexpectedly", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
	default:
		s.setSessionCookie(w, result.Token, result.ExpiresAt)
		writeJSON(w, http.StatusOK, sessionResponse{
			Username:  result.Account.Username,
			CSRFToken: result.CSRFToken,
			ExpiresAt: result.ExpiresAt,
		})
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil && cookie.Value != "" {
		if err := s.auth.Logout(r.Context(), cookie.Value,
			RequestID(r.Context()), clientIP(r)); err != nil {
			s.logger.Error("logout failed", "error", err.Error())
		}
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSessionInfo(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r)
	account := currentAccount(r)
	writeJSON(w, http.StatusOK, sessionResponse{
		Username:  account.Username,
		CSRFToken: session.CSRFToken,
		ExpiresAt: session.ExpiresAt,
	})
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	var req passwordChangeRequest
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.CurrentPassword) == 0 || len(req.CurrentPassword) > maxPasswordLen ||
		len(req.NewPassword) == 0 || len(req.NewPassword) > maxPasswordLen {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	cookie, _ := r.Cookie(sessionCookie)
	_, err := s.auth.ChangePassword(r.Context(), cookie.Value,
		req.CurrentPassword, req.NewPassword,
		RequestID(r.Context()), clientIP(r))
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "current password is incorrect")
	case errors.Is(err, auth.ErrWeakPassword):
		writeError(w, r, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
	case errors.Is(err, auth.ErrSessionInvalid):
		writeError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "session invalid or expired")
	case err != nil:
		s.logger.Error("password change failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
