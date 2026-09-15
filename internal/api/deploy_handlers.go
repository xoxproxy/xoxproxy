package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/store"
)

// configVersionResponse is the API shape of a configuration generation.
// It exposes only metadata — the rendered config itself contains
// credential verifiers and is never returned or stored here.
type configVersionResponse struct {
	Revision         int64     `json:"revision"`
	GeneratedAt      time.Time `json:"generated_at"`
	GeneratedBy      string    `json:"generated_by"`
	Reason           string    `json:"reason"`
	ValidationStatus string    `json:"validation_status"`
	DeploymentStatus string    `json:"deployment_status"`
	Checksum         string    `json:"checksum"`
}

func toConfigVersionResponse(v store.ConfigurationVersion) configVersionResponse {
	return configVersionResponse{
		Revision:         v.Revision,
		GeneratedAt:      v.GeneratedAt,
		GeneratedBy:      v.GeneratedBy,
		Reason:           v.Reason,
		ValidationStatus: v.ValidationStatus,
		DeploymentStatus: v.DeploymentStatus,
		Checksum:         v.Checksum,
	}
}

func (s *Server) handleConfigVersionList(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "limit must be 1-500")
			return
		}
		limit = n
	}
	versions, err := s.deploy.ListVersions(r.Context(), limit)
	if err != nil {
		s.logger.Error("config version list failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	out := make([]configVersionResponse, 0, len(versions))
	for _, v := range versions {
		out = append(out, toConfigVersionResponse(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out})
}

// handleEngineStatus reports deploy-pipeline health: engine running state
// and the last generation. Deliberately not a readiness check — an engine
// problem must never take the control plane with it (ARCHITECTURE.md,
// failure boundaries).
func (s *Server) handleEngineStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.deploy.Status(r.Context())
	if err != nil {
		s.logger.Error("engine status failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	resp := map[string]any{"running": status.EngineRunning}
	if status.LastDeploy != nil {
		resp["last_deploy"] = toConfigVersionResponse(*status.LastDeploy)
	} else {
		resp["last_deploy"] = nil
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDeployTrigger requests a manual redeploy. The work is asynchronous
// (a deploy includes a post-reload verify window); the config-versions
// history shows the outcome.
func (s *Server) handleDeployTrigger(w http.ResponseWriter, r *http.Request) {
	s.deploy.Trigger(actorFrom(r).Name, "manual")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}
