package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

type ctxKey string

const claimsCtxKey ctxKey = "cybernom_claims"

// RequireAuth validates the Bearer access token on every request. On
// success it injects Claims into the request context for downstream
// handlers; on failure it returns 401 without leaking why (invalid
// signature vs expired vs malformed all look identical to the caller).
func RequireAuth(issuer *TokenIssuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			tokenString := strings.TrimPrefix(header, "Bearer ")

			claims, err := issuer.Verify(tokenString, "access")
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), claimsCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole further restricts a route to a specific role. Must be chained
// after RequireAuth.
func RequireRole(role Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(claimsCtxKey).(*Claims)
			if !ok || claims.Role != role {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRoles restricts a route to one or more roles. Must be chained after RequireAuth.
func RequireRoles(roles ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(claimsCtxKey).(*Claims)
			if !ok {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			for _, role := range roles {
				if claims.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		})
	}
}

// ClaimsFromContext retrieves the authenticated caller's claims. Handlers
// should call this rather than re-parsing tokens.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsCtxKey).(*Claims)
	return claims, ok
}

// PerIPRateLimiter throttles requests per client IP to blunt
// credential-stuffing / brute-force / general flooding attacks. This is
// intentionally simple (in-memory, per-process) — it's the cheap first
// line of defense applied to every rate-limited route. For the login
// endpoint specifically, it runs in front of the shared, cross-replica,
// username-aware auth.SharedRateLimiter (see ratelimit.go), which is what
// actually holds the line once there's more than one replica behind a load
// balancer.
type PerIPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	r        rate.Limit
	burst    int
}

func NewPerIPRateLimiter(requestsPerSecond float64, burst int) *PerIPRateLimiter {
	return &PerIPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		r:        rate.Limit(requestsPerSecond),
		burst:    burst,
	}
}

func (l *PerIPRateLimiter) getLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, exists := l.limiters[ip]
	if !exists {
		lim = rate.NewLimiter(l.r, l.burst)
		l.limiters[ip] = lim
	}
	return lim
}

// Middleware applies the rate limit. clientIP should already account for
// trusted proxy headers being enabled/disabled (see server.trust_proxy_headers).
func (l *PerIPRateLimiter) Middleware(clientIP func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !l.getLimiter(ip).Allow() {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
