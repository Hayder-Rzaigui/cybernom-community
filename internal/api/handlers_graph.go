package api

import (
	"net/http"
	"strconv"
)

func (s *Server) handleListGraphAlerts(w http.ResponseWriter, r *http.Request) {
	s.listGraphSnapshots(w, r, "security_alert")
}

func (s *Server) handleListRiskySignins(w http.ResponseWriter, r *http.Request) {
	s.listGraphSnapshots(w, r, "risky_signin")
}

func (s *Server) listGraphSnapshots(w http.ResponseWriter, r *http.Request, kind string) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	snapshots, err := s.store.ListGraphSnapshots(r.Context(), kind, limit)
	if err != nil {
		s.log.Error("list graph snapshots failed", "kind", kind, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, snapshots)
}
