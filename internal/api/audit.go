package api

import (
	"net/http"

	"github.com/hayderrzaigui/cybernom/internal/storage"
)

// writeAudit records an audit entry for a handler action. It logs and
// swallows errors rather than failing the request: an audit-log write
// failure (e.g. a transient DB blip) should not block a viewer from
// acknowledging a real alert, but it should be visible in the server logs
// so a persistently broken audit trail gets noticed and fixed.
func (s *Server) writeAudit(r *http.Request, userID, username, action, alertID string) {
	err := s.store.WriteAudit(r.Context(), storage.AuditEntry{
		UserID:    userID,
		Username:  username,
		Action:    action,
		AlertID:   alertID,
		IPAddress: s.clientIP(r),
	})
	if err != nil {
		s.log.Error("audit log write failed", "error", err, "action", action, "username", username)
	}
}
