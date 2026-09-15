package api

import (
	"context"
	"net/http"

	"github.com/xoxproxy/xoxproxy/internal/buildinfo"
)

// requireSystem gates the system routes behind a wired metrics provider
// (nil only in reduced builds; 503 tells the operator what is missing).
func (s *Server) requireSystem(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.system == nil {
			writeError(w, r, http.StatusServiceUnavailable, "SYSTEM_METRICS_DISABLED",
				"system metrics are not available in this deployment")
			return
		}
		next(w, r)
	}
}

// systemStatusResponse is the Server page's identity card plus the
// control-plane's own view of its deployment (proxy ports, engine, TLS).
type systemStatusResponse struct {
	Hostname      string                  `json:"hostname"`
	OS            string                  `json:"os"`
	Platform      string                  `json:"platform"`
	Kernel        string                  `json:"kernel"`
	Arch          string                  `json:"arch"`
	UptimeSeconds uint64                  `json:"uptime_seconds"`
	PublicIP      string                  `json:"public_ip"` // best-effort; "" when egress is restricted
	EngineRunning bool                    `json:"engine_running"`
	LastDeploy    *configVersionResponse  `json:"last_deploy"`
	ProxyPorts    systemPorts             `json:"proxy_ports"`
	TLSEnabled    bool                    `json:"tls_enabled"`
	Version       string                  `json:"version"`
}

type systemPorts struct {
	HTTP   int `json:"http"`
	SOCKS5 int `json:"socks5"`
}

// DeploymentInfo is the static posture injected at boot: proxy ports from
// the validated config, TLS from the public base URL scheme, and the
// public-IP source (the system provider's cached lookup).
type DeploymentInfo struct {
	HTTPPort   int
	SOCKS5Port int
	TLS        bool
	PublicIP   func(ctx context.Context) string
}

// SetDeploymentInfo injects the deployment posture the status endpoint
// reports alongside host identity. Called once during boot.
func (s *Server) SetDeploymentInfo(info DeploymentInfo) { s.deployment = info }

// handleSystemStatus answers host identity plus deployment posture.
func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	identity, err := s.system.Identity(r.Context())
	if err != nil {
		s.logger.Error("system identity failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	engineStatus, err := s.deploy.Status(r.Context())
	if err != nil {
		s.logger.Error("engine status query failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	resp := systemStatusResponse{
		Hostname:      identity.Hostname,
		OS:            identity.OS,
		Platform:      identity.Platform,
		Kernel:        identity.Kernel,
		Arch:          identity.Arch,
		UptimeSeconds: identity.UptimeSec,
		EngineRunning: engineStatus.EngineRunning,
		ProxyPorts:    systemPorts{HTTP: s.deployment.HTTPPort, SOCKS5: s.deployment.SOCKS5Port},
		TLSEnabled:    s.deployment.TLS,
		Version:       buildinfo.Version,
	}
	if engineStatus.LastDeploy != nil {
		v := toConfigVersionResponse(*engineStatus.LastDeploy)
		resp.LastDeploy = &v
	}
	if s.deployment.PublicIP != nil {
		resp.PublicIP = s.deployment.PublicIP(r.Context())
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSystemResources answers a utilization snapshot: CPU, memory,
// swap, disk, network counters, load.
func (s *Server) handleSystemResources(w http.ResponseWriter, r *http.Request) {
	res, err := s.system.Resources(r.Context())
	if err != nil {
		s.logger.Error("system resources failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, res)
}
