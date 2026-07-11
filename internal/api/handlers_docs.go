package api

import (
	"net/http"
)

// handleAPIDocs serves a self-contained Swagger UI page for the /api/v1
// REST surface, embedded directly in the dashboard's "API Docs" tab via
// iframe. Loaded from cdnjs like Chart.js on /dashboard (see securityHeaders
// in router.go, which grants this path the same CSP allowance) rather than
// vendored, to keep the binary's embedded asset set small.
//
// This route is intentionally NOT behind auth.RequireAuth: it documents
// endpoint shapes only and contains no live data, matching how /dashboard's
// HTML shell itself is public while every JSON endpoint it calls still
// requires a bearer token. "Try it out" requests issued from the Swagger UI
// still need a real token pasted into its Authorization field to succeed.
func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	const page = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CyberNom API Docs</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css">
  <style>body{margin:0;background:#fff;}</style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-bundle.min.js"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: "/api/v1/openapi.json",
        dom_id: "#swagger-ui",
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

// handleOpenAPISpec serves a hand-maintained OpenAPI 3.0 description of the
// /api/v1 surface. It is intentionally not auto-generated (e.g. via
// swaggo/swag) to avoid adding a codegen step to the build; keep this in
// sync with router.go when routes change.
//
// The path descriptions themselves (which routes exist, and which roles
// they mention) come from editionOpenAPIPaths, which has one implementation
// per build tag (rbac_enterprise.go, rbac_community.go) — so a
// Community-built binary's docs never mention SIEM config or SOC-tier
// roles that don't exist in that build, and an Enterprise binary's docs
// accurately reflect its 4-tier RBAC.
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	spec := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "CyberNom API",
			"version":     "1.0.0",
			"description": "Threat intelligence platform REST API. All endpoints except /auth/login and /auth/refresh require a Bearer access token.",
		},
		"servers": []map[string]string{{"url": "/api/v1"}},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"bearerAuth": map[string]string{"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
			},
		},
		"security": []map[string][]string{{"bearerAuth": {}}},
		"paths":    editionOpenAPIPaths(),
	}
	writeJSON(w, http.StatusOK, spec)
}

func simplePath(method, summary string, requiresAuth bool) map[string]interface{} {
	op := map[string]interface{}{
		"summary": summary,
		"responses": map[string]interface{}{
			"200": map[string]string{"description": "OK"},
			"401": map[string]string{"description": "Unauthorized"},
			"403": map[string]string{"description": "Forbidden — insufficient role"},
		},
	}
	if requiresAuth {
		op["security"] = []map[string][]string{{"bearerAuth": {}}}
	} else {
		op["security"] = []map[string][]string{}
	}
	return map[string]interface{}{method: op}
}
