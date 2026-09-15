package api

import (
	"net/http"
	"os"
	"strconv"
)

// maxEngineLogLines bounds the tail: the Logs page renders at most a few
// hundred lines; anything more is a job for the operator's shell, not the
// API.
const (
	defaultEngineLogLines = 100
	maxEngineLogLines     = 500
)

// handleEngineLogTail answers GET /api/v1/logs/engine?limit=N with the
// last N lines of the engine traffic log, oldest first. Read-only: the
// log belongs to the engine; the control plane never writes it. Lines are
// returned raw (they are the engine's own format) — the dashboard parses
// or displays them as text.
func (s *Server) handleEngineLogTail(w http.ResponseWriter, r *http.Request) {
	limit := defaultEngineLogLines
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxEngineLogLines {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST",
				"limit must be 1-"+strconv.Itoa(maxEngineLogLines))
			return
		}
		limit = n
	}

	if s.trafficLogPath == "" {
		writeError(w, r, http.StatusServiceUnavailable, "ENGINE_LOG_DISABLED",
			"engine log path is not configured in this deployment")
		return
	}

	lines, err := tailLines(s.trafficLogPath, limit)
	if err != nil {
		if os.IsNotExist(err) {
			// The engine has not written a log yet — an empty view, not
			// an error.
			writeJSON(w, http.StatusOK, map[string]any{"lines": []string{}})
			return
		}
		s.logger.Error("engine log tail failed", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
}

// tailLines returns the last n lines of the file, oldest first. The file
// is bounded in practice (engine rotation), so a full read with a ring of
// the final n lines is simpler and safer than seeking backwards.
func tailLines(path string, n int) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var all []string
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			line := string(data[start:i])
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			all = append(all, line)
			start = i + 1
		}
	}
	if start < len(data) {
		all = append(all, string(data[start:]))
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}
