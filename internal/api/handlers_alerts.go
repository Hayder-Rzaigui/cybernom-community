package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/hayderrzaigui/cybernom/internal/auth"
)

// handleListAlerts also doubles as the audit trail's "view" event: since
// alerts frequently contain sensitive material (leaked credentials, PII in
// snippets), recording who pulled the list and when matters even though
// this route is read-only. One audit row is written per list call, not per
// alert returned, to avoid drowning the trail in near-duplicate rows on
// every 20-second dashboard poll — see docs/THREAT_MODEL.md if that
// granularity ever needs to change.
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}
	severity := r.URL.Query().Get("severity")
	if severity != "" {
		switch severity {
		case "low", "medium", "high", "critical":
			// valid
		default:
			writeError(w, http.StatusBadRequest, "severity must be one of: low, medium, high, critical")
			return
		}
	}

	alerts, err := s.store.ListAlerts(r.Context(), limit, severity)
	if err != nil {
		s.log.Error("list alerts failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if claims, ok := auth.ClaimsFromContext(r.Context()); ok {
		s.writeAudit(r, claims.UserID, claims.Username, "alert.view", "")
	}

	writeJSON(w, http.StatusOK, alerts)
}

func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing alert id")
		return
	}
	if err := s.store.AcknowledgeAlert(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}

	if claims, ok := auth.ClaimsFromContext(r.Context()); ok {
		s.writeAudit(r, claims.UserID, claims.Username, "alert.ack", id)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

// handleResolveAlert marks an alert resolved. Distinct from Acknowledge:
// acknowledging says "someone has seen this and is on it" (new -> in_triage),
// resolving says "this is done" (-> resolved) and is what feeds the SLA
// compliance widget, since only resolved alerts have a resolution time to
// measure against their SLA target.
func (s *Server) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing alert id")
		return
	}
	if err := s.store.ResolveAlert(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}

	if claims, ok := auth.ClaimsFromContext(r.Context()); ok {
		s.writeAudit(r, claims.UserID, claims.Username, "alert.resolve", id)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "resolved"})
}

// handleListAudit is restricted to Admin and Compliance Auditor (enforced
// by RequireRoles in the router). Optionally scoped to a single alert via
// ?alert_id=, to answer "who has seen or acted on this specific alert"
// directly.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	alertID := r.URL.Query().Get("alert_id")

	entries, err := s.store.ListAudit(r.Context(), limit, alertID)
	if err != nil {
		s.log.Error("list audit log failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}
