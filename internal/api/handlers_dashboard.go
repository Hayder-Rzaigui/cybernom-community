package api

import (
	"embed"
	"io/fs"
	"net/http"
)

// webFS embeds the static dashboard UI directly into the compiled binary —
// no separate static file directory to deploy or misconfigure permissions
// on. The dashboard is a thin client over the existing JSON API: it carries
// no server-side session state and enforces no authorization itself, all
// auth still happens via the same JWT-protected /api/v1 routes.
//
//go:embed web/dashboard.html
var webFS embed.FS

// handleDashboard serves the single-page alerts dashboard. It is
// intentionally NOT behind auth.RequireAuth: the page itself contains no
// data, only the JS that calls the authenticated JSON API and renders a
// login form if there's no valid session. Serving the shell HTML publicly
// while still requiring a valid JWT for every data-bearing request is the
// same pattern used by any SPA.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFileFS(w, r, sub, "dashboard.html")
}
