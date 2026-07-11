// Package api wires the HTTP surface: routing, middleware chain (auth, rate
// limiting, request logging), and handlers.
//
// This file is edition-agnostic: it never references anything gated behind
// the `enterprise` build tag (RBAC role granularity, SIEM forwarding, the
// encrypted secrets vault). Those are registered via registerRBACRoutes,
// which has exactly one implementation per edition:
//   - rbac_enterprise.go (build tag enterprise)
//   - rbac_community.go  (build tag !enterprise)
//
// Similarly, the Server fields specific to SIEM/vault plumbing
// (vault, forwarder, SetSecretsVault, SetSIEMForwarder) live in
// server_enterprise.go / server_community.go, not here — this file only
// ever touches fields that exist in both editions.
package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/hayderrzaigui/cybernom/internal/auth"
	"github.com/hayderrzaigui/cybernom/internal/config"
	"github.com/hayderrzaigui/cybernom/internal/storage"
)

// Server bundles everything a handler needs. Fields here are shared across
// both editions; edition-specific fields (vault, forwarder) are declared on
// an embedded type — see server_enterprise.go / server_community.go.
type Server struct {
	cfg       *config.Config
	log       *slog.Logger
	store     *storage.Store
	tokens    *auth.TokenIssuer
	rateLimit *auth.PerIPRateLimiter  // coarse, in-memory, first line of defense on every rate-limited route
	loginRate *auth.SharedRateLimiter // shared across replicas, IP+username aware, login-specific

	edition editionState // enterprise: vault + forwarder; community: empty struct
}

func NewServer(cfg *config.Config, log *slog.Logger, store *storage.Store, tokens *auth.TokenIssuer) *Server {
	return &Server{
		cfg:       cfg,
		log:       log,
		store:     store,
		tokens:    tokens,
		rateLimit: auth.NewPerIPRateLimiter(cfg.Server.RateLimitRPS, int(cfg.Server.RateLimitRPS*2)+1),
		// 10 attempts per 5-minute window, per bucket key (IP or username).
		// Deliberately looser than the per-process limiter above: this one
		// is the backstop that still works correctly with N replicas behind
		// a load balancer, not the primary throttle.
		loginRate: auth.NewSharedRateLimiter(store.Pool(), 10, 5*time.Minute),
	}
}

// Router builds the full chi router with the security middleware chain
// applied in order: request ID -> real IP -> structured logging -> recover
// -> security headers -> (per-route) rate limit / auth.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	if s.cfg.Server.TrustProxyHeaders {
		r.Use(middleware.RealIP)
	}
	r.Use(s.requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)
	r.Get("/dashboard", s.handleDashboard)

	// API documentation: public/unauthenticated, like /dashboard's HTML
	// shell — it describes endpoint shapes only, no live data. See
	// handlers_docs.go.
	r.Get("/api/v1/docs", s.handleAPIDocs)
	r.Get("/api/v1/openapi.json", s.handleOpenAPISpec)

	r.Route("/api/v1", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			// Order matters: the cheap in-memory per-process limiter runs
			// first and rejects obvious floods without touching Postgres;
			// the shared limiter behind it is what actually holds the line
			// once there's more than one replica, and is what makes
			// per-username throttling possible at all.
			r.Use(s.rateLimit.Middleware(s.clientIP))
			r.Use(s.loginRate.LoginRateLimitMiddleware(s.clientIP))
			r.Post("/auth/login", s.handleLogin)
			r.Post("/auth/refresh", s.handleRefresh)
		})

		r.Group(func(r chi.Router) {
			r.Use(auth.RequireAuth(s.tokens))

			// Routes with no role-granularity distinction between editions
			// live here, unconditionally. Anything whose access varies by
			// role tier (including "does this role exist at all") is
			// registered by registerRBACRoutes below instead.
			r.Get("/dashboard-metrics", s.handleDashboardMetrics)
			r.Get("/alerts", s.handleListAlerts)
			r.Post("/alerts/{id}/ack", s.handleAckAlert)
			r.Post("/alerts/{id}/resolve", s.handleResolveAlert)
			r.Get("/feeds", s.handleListFeeds)
			r.Get("/feeds/{id}", s.handleGetFeed)
			r.Get("/feeds/{id}/stats", s.handleGetFeedStats)
			r.Get("/graph/security-alerts", s.handleListGraphAlerts)
			r.Get("/graph/risky-signins", s.handleListRiskySignins)

			// Edition-specific: role-gated management routes (feed
			// create/toggle/delete, user creation), the audit trail, and
			// (Enterprise only) SIEM config. See rbac_enterprise.go /
			// rbac_community.go.
			s.registerRBACRoutes(r)
		})
	})

	return r
}

// clientIP resolves the caller's IP, honoring X-Forwarded-For / X-Real-IP
// ONLY when trust_proxy_headers is explicitly enabled — otherwise those
// headers are attacker-controlled and would let a client spoof its way
// around rate limiting.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.Server.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		s.log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}

// securityHeaders sets baseline defensive headers on every response. The
// JSON API (everything except /dashboard and /api/v1/docs) keeps the
// strictest possible policy, since it never serves anything a browser
// should render or execute. /dashboard and /api/v1/docs ARE browser-rendered
// pages, so they get a narrowly scoped policy instead: no third-party
// origins except cdnjs.cloudflare.com, for Chart.js on /dashboard and for
// swagger-ui's bundle/CSS on /api/v1/docs specifically (see dashboard.html
// and handlers_docs.go — vendoring these locally was not possible in the
// environment this was built in; if you later self-host them, tighten this
// back to 'self' and drop the cdnjs allowance). No framing of either page
// by third-party sites; /dashboard may itself frame same-origin content
// (used to embed /api/v1/docs in its "API Docs" tab), and may call back to
// this same origin's JSON API.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		switch r.URL.Path {
		case "/dashboard":
			h.Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "+
					"style-src 'self' 'unsafe-inline'; "+
					"connect-src 'self'; img-src 'self' data:; frame-src 'self'; "+
					"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		case "/api/v1/docs":
			h.Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "+
					"style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "+
					"connect-src 'self'; img-src 'self' data:; "+
					"frame-ancestors 'self'; base-uri 'none'; form-action 'none'")
		default:
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		}
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
