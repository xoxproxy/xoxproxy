package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// userResponse is the API shape of a proxy user. It deliberately contains
// no credential material: hashes never leave the server, and the plaintext
// password appears only in the create/rotate response, exactly once.
type userResponse struct {
	ID                int64      `json:"id"`
	Username          string     `json:"username"`
	Status            string     `json:"status"`
	AllowedProtocols  []string   `json:"allowed_protocols"`
	DownloadBPS       int64      `json:"download_limit_bps"`
	UploadBPS         int64      `json:"upload_limit_bps"`
	MaxConnections    int64      `json:"max_connections"`
	QuotaBytesDaily   int64      `json:"quota_bytes_daily"`
	QuotaBytesMonthly int64      `json:"quota_bytes_monthly"`
	ExpiresAt         *time.Time `json:"expires_at"`
	Version           int64      `json:"version"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	LastSeenAt        *time.Time `json:"last_seen_at"`
}

// oneTimeCredential is returned only by create and rotate-credentials: the
// password exists in the response body once and is never recoverable
// afterwards.
type oneTimeCredential struct {
	userResponse
	Password string `json:"password"`
}

func toUserResponse(u store.ProxyUser) userResponse {
	protocols := u.AllowedProtocols
	if protocols == nil {
		protocols = []string{}
	}
	return userResponse{
		ID:                u.ID,
		Username:          u.Username,
		Status:            u.Status,
		AllowedProtocols:  protocols,
		DownloadBPS:       u.DownloadBPS,
		UploadBPS:         u.UploadBPS,
		MaxConnections:    u.MaxConnections,
		QuotaBytesDaily:   u.QuotaBytesDaily,
		QuotaBytesMonthly: u.QuotaBytesMonthly,
		ExpiresAt:         u.ExpiresAt,
		Version:           u.Version,
		CreatedAt:         u.CreatedAt,
		UpdatedAt:         u.UpdatedAt,
		LastSeenAt:        u.LastSeenAt,
	}
}

// --- request shapes ---

type createUserRequest struct {
	Username          string     `json:"username"`
	Password          string     `json:"password"` // optional; generated when empty
	AllowedProtocols  []string   `json:"allowed_protocols"`
	DownloadBPS       int64      `json:"download_limit_bps"`
	UploadBPS         int64      `json:"upload_limit_bps"`
	MaxConnections    int64      `json:"max_connections"`
	QuotaBytesDaily   int64      `json:"quota_bytes_daily"`
	QuotaBytesMonthly int64      `json:"quota_bytes_monthly"`
	ExpiresAt         *time.Time `json:"expires_at"`
}

type updateUserRequest struct {
	Version           int64      `json:"version"`
	AllowedProtocols  *[]string  `json:"allowed_protocols"`
	DownloadBPS       *int64     `json:"download_limit_bps"`
	UploadBPS         *int64     `json:"upload_limit_bps"`
	MaxConnections    *int64     `json:"max_connections"`
	QuotaBytesDaily   *int64     `json:"quota_bytes_daily"`
	QuotaBytesMonthly *int64     `json:"quota_bytes_monthly"`
	ExpiresAt         *time.Time `json:"expires_at"`
	ClearExpiration   bool       `json:"clear_expiration"`
}

type userActionRequest struct {
	Version int64 `json:"version"`
}

func actorFrom(r *http.Request) users.Actor {
	account := currentAccount(r)
	return users.Actor{
		Name:      account.Username,
		RequestID: RequestID(r.Context()),
		SourceIP:  clientIP(r),
		UserAgent: r.UserAgent(),
	}
}

// --- handlers ---

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseUserFilter(w, r)
	if !ok {
		return
	}
	list, err := s.users.List(r.Context(), filter)
	if err != nil {
		s.logger.Error("user list failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	out := make([]userResponse, 0, len(list))
	for _, u := range list {
		out = append(out, toUserResponse(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !readJSON(w, r, &req) {
		return
	}
	user, password, err := s.users.Create(r.Context(), users.CreateInput{
		Username:          req.Username,
		Password:          req.Password,
		Protocols:         req.AllowedProtocols,
		DownloadBPS:       req.DownloadBPS,
		UploadBPS:         req.UploadBPS,
		MaxConnections:    req.MaxConnections,
		QuotaBytesDaily:   req.QuotaBytesDaily,
		QuotaBytesMonthly: req.QuotaBytesMonthly,
		ExpiresAt:         req.ExpiresAt,
	}, actorFrom(r))
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	resp := oneTimeCredential{userResponse: toUserResponse(user), Password: password}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleUserGet(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	user, err := s.users.Get(r.Context(), id)
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(user))
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	var req updateUserRequest
	if !readJSON(w, r, &req) {
		return
	}
	user, err := s.users.Update(r.Context(), id, users.UpdateInput{
		Version:           req.Version,
		Protocols:         req.AllowedProtocols,
		DownloadBPS:       req.DownloadBPS,
		UploadBPS:         req.UploadBPS,
		MaxConnections:    req.MaxConnections,
		QuotaBytesDaily:   req.QuotaBytesDaily,
		QuotaBytesMonthly: req.QuotaBytesMonthly,
		ExpiresAt:         req.ExpiresAt,
		ClearExpiration:   req.ClearExpiration,
	}, actorFrom(r))
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(user))
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	if err := s.users.Delete(r.Context(), id, actorFrom(r)); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleUserRotate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"` // optional; generated when empty
	}
	if !readJSON(w, r, &req) {
		return
	}
	user, password, err := s.users.RotateCredentials(r.Context(), id, req.Password, actorFrom(r))
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, oneTimeCredential{userResponse: toUserResponse(user), Password: password})
}

func (s *Server) handleUserDisable(w http.ResponseWriter, r *http.Request) {
	s.handleUserStatusAction(w, r, "disable")
}

func (s *Server) handleUserEnable(w http.ResponseWriter, r *http.Request) {
	s.handleUserStatusAction(w, r, "enable")
}

func (s *Server) handleUserStatusAction(w http.ResponseWriter, r *http.Request, op string) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	version, ok := decodeVersionAction(w, r)
	if !ok {
		return
	}
	var (
		user store.ProxyUser
		err  error
	)
	if op == "disable" {
		user, err = s.users.Disable(r.Context(), id, version, actorFrom(r))
	} else {
		user, err = s.users.Enable(r.Context(), id, version, actorFrom(r))
	}
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(user))
}

// writeUserError maps service errors onto the API error envelope. Internal
// error text never crosses the boundary.
func (s *Server) writeUserError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
	case errors.Is(err, users.ErrUsernameTaken):
		writeError(w, r, http.StatusConflict, "USERNAME_TAKEN", "username already taken")
	case errors.Is(err, users.ErrVersionConflict):
		writeError(w, r, http.StatusConflict, "VERSION_CONFLICT", "user was modified concurrently; reload and retry")
	case errors.Is(err, users.ErrExpired):
		writeError(w, r, http.StatusBadRequest, "USER_EXPIRED", "user's expiry has passed; extend expires_at first")
	case errors.Is(err, users.ErrInvalidInput), errors.Is(err, users.ErrWeakPassword):
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
	default:
		s.logger.Error("user operation failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
	}
}

// handleUserResetQuota zeroes the user's current-window usage in the
// ledger. The body carries the optimistic-lock version for API symmetry
// with the other actions; the user row itself is not mutated.
func (s *Server) handleUserResetQuota(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUserID(w, r)
	if !ok {
		return
	}
	if _, ok := decodeVersionAction(w, r); !ok {
		return
	}
	user, err := s.users.ResetQuota(r.Context(), id, actorFrom(r))
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(user))
}

// --- path/query parsing ---

// parseUserID extracts the {id} path value. Non-numeric ids are 400 —
// never passed to the storage layer.
func parseUserID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, r, http.StatusBadRequest, "INVALID_ID", "user id must be a positive integer")
		return 0, false
	}
	return id, true
}

func parseUserFilter(w http.ResponseWriter, r *http.Request) (store.UserFilter, bool) {
	q := r.URL.Query()
	filter := store.UserFilter{Limit: 100}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "limit must be 1-500")
			return store.UserFilter{}, false
		}
		filter.Limit = n
	}
	if v := q.Get("before_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "before_id must be a positive integer")
			return store.UserFilter{}, false
		}
		filter.BeforeID = n
	}
	if v := q.Get("status"); v != "" {
		switch v {
		case store.UserActive, store.UserDisabled, store.UserExpired:
			filter.Status = v
		default:
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "status must be active, disabled or expired")
			return store.UserFilter{}, false
		}
	}
	return filter, true
}

// decodeVersionAction parses the body of status actions, which carry only
// the optimistic-lock version.
func decodeVersionAction(w http.ResponseWriter, r *http.Request) (int64, bool) {
	var req userActionRequest
	if !readJSON(w, r, &req) {
		return 0, false
	}
	if req.Version < 1 {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "version is required")
		return 0, false
	}
	return req.Version, true
}
