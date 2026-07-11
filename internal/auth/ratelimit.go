package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SharedRateLimiter implements a fixed-window counter backed by Postgres,
// so the limit is enforced correctly across every replica of the process
// rather than resetting per-instance the way an in-memory limiter does.
// It is intentionally simple: one row per bucket key, a window start time,
// and a count, reset via UPSERT when the window has elapsed.
//
// This replaces the old in-memory-only, IP-only limiter for the login
// endpoint specifically, where both failure modes matter:
//   - a distributed attacker rotating source IPs against one username
//   - a single IP behind CGNAT/proxy hammering many usernames
//
// Both are covered by calling Allow twice with different bucket keys (see
// LoginRateLimitMiddleware below) rather than folding them into one key,
// so a legitimate office IP with one slow typist doesn't get penalized for
// an unrelated user being attacked from the same egress IP.
type SharedRateLimiter struct {
	pool   *pgxpool.Pool
	window time.Duration
	max    int
}

// NewSharedRateLimiter builds a limiter allowing `max` actions per `window`
// per bucket key.
func NewSharedRateLimiter(pool *pgxpool.Pool, max int, window time.Duration) *SharedRateLimiter {
	return &SharedRateLimiter{pool: pool, max: max, window: window}
}

// Allow atomically increments the counter for key and reports whether the
// action should proceed. It resets the window transparently once expired.
// Implemented as a single UPSERT + conditional so concurrent requests
// racing on the same key still serialize correctly via Postgres's row lock,
// rather than needing an external mutex.
func (l *SharedRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	now := time.Now().UTC()

	var count int
	var windowStart time.Time
	err := l.pool.QueryRow(ctx, `
		INSERT INTO rate_limit_counters (bucket_key, window_start, count)
		VALUES ($1, $2, 1)
		ON CONFLICT (bucket_key) DO UPDATE SET
			window_start = CASE
				WHEN rate_limit_counters.window_start < $3 THEN $2
				ELSE rate_limit_counters.window_start
			END,
			count = CASE
				WHEN rate_limit_counters.window_start < $3 THEN 1
				ELSE rate_limit_counters.count + 1
			END
		RETURNING window_start, count`,
		key, now, now.Add(-l.window),
	).Scan(&windowStart, &count)
	if err != nil {
		return false, fmt.Errorf("auth: rate limit check failed: %w", err)
	}

	return count <= l.max, nil
}

// LoginRateLimitMiddleware enforces two independent limits on the login
// endpoint: one keyed by client IP, one keyed by the attempted username
// (read from the request body without consuming it, so downstream handlers
// still see the full body). Either limit tripping blocks the request.
//
// Fails open on limiter errors (e.g. a transient DB blip) rather than
// locking every user out because Postgres hiccuped — the in-memory
// per-process limiter in middleware.go remains as a coarse first line of
// defense in front of this one and does not depend on the database.
func (l *SharedRateLimiter) LoginRateLimitMiddleware(clientIP func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)

			ipOK, err := l.Allow(r.Context(), "ip:"+ip)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			if !ipOK {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			username := peekUsername(r)
			if username != "" {
				userOK, err := l.Allow(r.Context(), "user:"+strings.ToLower(username))
				if err == nil && !userOK {
					http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// peekUsername extracts the "username" field from a JSON request body
// without consuming it for downstream handlers: the body is read fully,
// parsed, then replaced with a fresh reader over the same bytes. Capped at
// 1 MiB, matching decodeJSON's limit, so a huge body can't be used to stall
// this middleware. Returns "" on any read/parse failure — the request is
// still rate-limited by IP in that case, and handleLogin will reject a
// malformed body on its own.
func peekUsername(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var payload struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.Username
}
