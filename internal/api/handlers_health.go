package api

import "net/http"

// handleHealth is a liveness probe — always returns 200 if the process is
// running and able to handle HTTP at all. Does not touch the database.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady is a readiness probe — verifies the database is reachable.
// Kubernetes/Compose healthchecks should use this, not /healthz, to decide
// whether to route traffic to this instance.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, err := s.store.ListAlerts(ctx, 1, ""); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
