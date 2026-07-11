//go:build !enterprise

package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hayderrzaigui/cybernom/internal/auth"
)

// registerRBACRoutes wires every route whose access depends on role, using
// Community Edition's 2-role model (admin/viewer — see roles_community.go).
// There is no SOC-tier/Compliance-Auditor granularity in this build: Admin
// gets every management action, Viewer gets read/export access to
// everything else. r is already wrapped in auth.RequireAuth by the caller
// (router.go).
//
// SIEM configuration (GET/PUT /siem-config...) is an Enterprise-only
// feature (ENTERPRISE.md section 3); it isn't silently dropped from the
// route table here — it's registered as a stub that always returns 403
// with a clear "Feature unavailable in Community Edition" body, so a
// Community operator hitting these routes gets an explicit, actionable
// answer rather than a bare 404.
func (s *Server) registerRBACRoutes(r chi.Router) {
	// Read/export access: Admin and Viewer both get these — they're
	// read-only actions, and Community has no Compliance-Auditor-style
	// role to exclude from alert-level exports the way Enterprise does.
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireRoles(auth.RoleAdmin, auth.RoleViewer))
		r.Get("/audit", s.handleListAudit)
		r.Get("/export/audit.csv", s.handleExportAuditLogCSV)
		r.Get("/export/alerts.csv", s.handleExportAlertsCSV)
		r.Get("/export/report.json", s.handleExportPDFReport)
	})

	// Feed and user management: Admin-only, matching the base README's
	// documented API table (admin/viewer split).
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireRole(auth.RoleAdmin))
		r.Put("/feeds/{id}/enabled", s.handleToggleFeed)
		r.Post("/feeds", s.handleCreateFeed)
		r.Delete("/feeds/{id}", s.handleDeleteFeed)
		r.Post("/users", s.handleCreateUser)
	})

	// SIEM configuration: Enterprise-only. Registered here (rather than
	// left unregistered) so hitting these routes on a Community binary
	// returns a clear, explicit "not available in this edition" response
	// instead of a bare 404 that looks like a routing bug. Still
	// requires authentication (applied by the caller) and Admin, matching
	// the role that would own this surface if it existed in this build.
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireRole(auth.RoleAdmin))
		r.Get("/siem-config", s.handleEnterpriseFeatureUnavailable)
		r.Put("/siem-config/{type}", s.handleEnterpriseFeatureUnavailable)
	})
}

// handleEnterpriseFeatureUnavailable is the Community-edition response for
// any route that exists only in Enterprise builds. Returns 403 rather than
// 404 (or a silent success) so operators get a clear, actionable signal —
// see ENTERPRISE.md for the feature list and how to switch editions.
func (s *Server) handleEnterpriseFeatureUnavailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error":   "feature_unavailable",
		"message": "This feature requires CyberNom Enterprise Edition (built with -tags enterprise). See ENTERPRISE.md.",
	})
}

// editionOpenAPIPaths is the Community build's contribution to
// handleOpenAPISpec (handlers_docs.go): every route this edition serves,
// annotated with its actual 2-role RBAC requirement. Unlike Enterprise's
// version of this function, role descriptions never mention SOC tiers or
// Compliance Auditor (they don't exist in this build), and siem-config is
// explicitly documented as returning 403 rather than described as if it
// worked.
func editionOpenAPIPaths() map[string]interface{} {
	return map[string]interface{}{
		"/auth/login":            simplePath("post", "Authenticate and receive access/refresh tokens", false),
		"/auth/refresh":          simplePath("post", "Exchange a refresh token for a new access token", false),
		"/alerts":                simplePath("get", "List alerts (Admin, Viewer)", true),
		"/alerts/{id}/ack":       simplePath("post", "Acknowledge an alert (triage)", true),
		"/alerts/{id}/resolve":   simplePath("post", "Resolve an alert", true),
		"/dashboard-metrics":     simplePath("get", "Aggregate dashboard metrics (all roles)", true),
		"/audit":                 simplePath("get", "List audit log entries (Admin, Viewer)", true),
		"/export/alerts.csv":     simplePath("get", "Export filtered alert history as CSV (Admin, Viewer)", true),
		"/export/audit.csv":      simplePath("get", "Export audit log as CSV (Admin, Viewer)", true),
		"/export/report.json":    simplePath("get", "SLA compliance / MTTR / volume summary (Admin, Viewer)", true),
		"/feeds":                 simplePath("get", "List threat feeds", true),
		"/feeds/{id}":            simplePath("get", "Get a single threat feed", true),
		"/feeds/{id}/enabled":    simplePath("put", "Enable/disable a feed instantly (Admin only)", true),
		"/feeds/{id}/stats":      simplePath("get", "Most recent poll statistics for a feed", true),
		"/users":                 simplePath("post", "Create a user (Admin only)", true),
		"/siem-config":           simplePath("get", "Not available in Community Edition — always returns 403 (see ENTERPRISE.md)", true),
		"/siem-config/{type}":    simplePath("put", "Not available in Community Edition — always returns 403 (see ENTERPRISE.md)", true),
		"/graph/security-alerts": simplePath("get", "Microsoft Graph security alert snapshots", true),
		"/graph/risky-signins":   simplePath("get", "Microsoft Graph risky sign-in snapshots", true),
	}
}
