package storage

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hayderrzaigui/cybernom/internal/config"
	"github.com/hayderrzaigui/cybernom/internal/ingester"
	"github.com/hayderrzaigui/cybernom/internal/ingester/fetchers"
	"github.com/hayderrzaigui/cybernom/internal/notifier"
	"github.com/hayderrzaigui/cybernom/internal/siem"
)

// Store wraps a Postgres connection pool. All queries in this file use
// parameterized placeholders ($1, $2, ...) exclusively — there is no
// string-concatenated SQL anywhere in this package, by convention enforced
// via code review / linting (see .golangci.yml) rather than by the
// language itself.
type Store struct {
	pool      *pgxpool.Pool
	router    *notifier.Router     // optional: if set, HandleMatch also dispatches notifications
	forwarder siem.AlertForwarder  // optional: if set, HandleMatch also forwards verified alerts to external SIEM platforms
}

// Open establishes the connection pool. The password is read from the
// environment variable named in cfg.PasswordEnvVar — never from YAML.
func Open(ctx context.Context, cfg config.DatabaseConfig) (*Store, error) {
	password := os.Getenv(cfg.PasswordEnvVar)
	if password == "" {
		return nil, fmt.Errorf("storage: db password env var %q is not set", cfg.PasswordEnvVar)
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s pool_max_conns=%d",
		cfg.Host, cfg.Port, cfg.Name, cfg.User, password, cfg.SSLMode, cfg.MaxOpenConns,
	)

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: parsing dsn: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("storage: creating pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("storage: ping failed: %w", err)
	}

	return &Store{pool: pool}, nil
}

// WithRouter attaches a notification router so that HandleMatch (invoked by
// the ingester engine as an ingester.AlertSink) both persists AND notifies.
func (s *Store) WithRouter(r *notifier.Router) *Store {
	s.router = r
	return s
}

// WithSIEMForwarder attaches an outbound SIEM forwarder so that HandleMatch
// also forwards each newly-verified alert to any configured external SIEM
// (syslog/Splunk/Sentinel) in addition to persisting it and dispatching
// user-facing notifications. Passing nil disables forwarding.
//
// Takes the siem.AlertForwarder interface rather than the concrete
// Enterprise *siem.Forwarder type specifically so this package compiles
// identically in both editions: main.go calls siem.NewForwarder(...) either
// way, and the returned type (Enterprise's real *Forwarder or Community's
// *NoopForwarder) is passed straight through here without either side
// needing a build tag of its own.
func (s *Store) WithSIEMForwarder(f siem.AlertForwarder) *Store {
	s.forwarder = f
	return s
}

func (s *Store) Close() {
	s.pool.Close()
}

// Pool exposes the underlying connection pool for subsystems that need
// direct Postgres access outside the Store's own query methods — currently
// only auth.SharedRateLimiter, which needs a shared counter table that
// isn't otherwise part of the domain model this package exposes.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// --- ingester.AlertSink implementation ---

var _ ingester.AlertSink = (*Store)(nil)

func (s *Store) HandleMatch(ctx context.Context, item fetchers.Item, match ingester.MatchResult) error {
	var alertID string
	createdAt := time.Now().UTC()
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alerts (keyword_name, severity, source_feed, item_title, item_url, snippet, tags, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`,
		match.Keyword, match.Severity, item.SourceFeed, item.Title, item.URL, match.Snippet, match.Tags, createdAt,
	).Scan(&alertID)
	if err != nil {
		return fmt.Errorf("storage: inserting alert: %w", err)
	}

	if s.router != nil {
		s.router.Dispatch(ctx, notifier.Alert{
			KeywordName: match.Keyword,
			Severity:    match.Severity,
			Tags:        match.Tags,
			SourceFeed:  item.SourceFeed,
			ItemTitle:   item.Title,
			ItemURL:     item.URL,
			Snippet:     match.Snippet,
		})
	}

	// Forward this verified alert to any configured external SIEM. This
	// runs synchronously but ForwardAlert itself is designed to fail soft
	// (logged warnings, not errors) on any transient network issue, so a
	// slow or unreachable SIEM endpoint does not block or fail ingestion.
	if s.forwarder != nil {
		s.forwarder.ForwardAlert(&siem.AlertPayload{
			ID:          alertID,
			KeywordName: match.Keyword,
			Severity:    match.Severity,
			SourceFeed:  item.SourceFeed,
			ItemTitle:   item.Title,
			ItemURL:     item.URL,
			Snippet:     match.Snippet,
			Tags:        match.Tags,
			Status:      "new",
			CreatedAt:   createdAt,
		})
	}
	return nil
}

// --- Alerts API ---

func (s *Store) ListAlerts(ctx context.Context, limit int, minSeverity string) ([]Alert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, keyword_name, severity, source_feed, item_title, item_url, snippet, tags, acknowledged, status, resolved_at, created_at
		FROM alerts
		WHERE ($2 = '' OR severity = $2)
		ORDER BY created_at DESC
		LIMIT $1`,
		limit, minSeverity,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: querying alerts: %w", err)
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.KeywordName, &a.Severity, &a.SourceFeed, &a.ItemTitle, &a.ItemURL, &a.Snippet, &a.Tags, &a.Acknowledged, &a.Status, &a.ResolvedAt, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("storage: scanning alert row: %w", err)
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// AcknowledgeAlert moves an alert from "new" to "in_triage". It does not
// downgrade an already-resolved alert back to in_triage — acknowledging
// something that's already resolved is a no-op on status, matching how an
// analyst would expect "Acknowledge" vs "Resolve" to behave as a one-way
// forward progression rather than two independent toggles.
func (s *Store) AcknowledgeAlert(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE alerts SET status = 'in_triage'
		WHERE id = $1 AND status = 'new'`, id)
	if err != nil {
		return fmt.Errorf("storage: acknowledging alert: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguish "doesn't exist" from "already past new" so the
		// handler can return 404 only for the former.
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM alerts WHERE id = $1)`, id).Scan(&exists); err != nil {
			return fmt.Errorf("storage: checking alert existence: %w", err)
		}
		if !exists {
			return fmt.Errorf("storage: alert %s not found", id)
		}
	}
	return nil
}

// ResolveAlert marks an alert resolved. resolved_at is set by the
// sync_alert_acknowledged trigger (migration 0002), not here, so the
// timestamp is always assigned by the database rather than app-server
// clocks, which avoids skew between replicas.
func (s *Store) ResolveAlert(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE alerts SET status = 'resolved' WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("storage: resolving alert: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: alert %s not found", id)
	}
	return nil
}

// --- Dashboard metrics API ---
//
// These back the widget-grid dashboard: severity/status/SLA donuts, the
// category breakdown, the 7-day trend line, and the per-source stacked
// bar. All are plain aggregate queries over the alerts table (plus
// sla_targets / source_categories for the two that need config), computed
// on request rather than cached — alert volumes here are low enough
// (hundreds to low thousands of rows) that this is cheap; revisit with a
// materialized view if that stops being true.

func (s *Store) SeverityCounts(ctx context.Context) (SeverityCounts, error) {
	var c SeverityCounts
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE severity = 'critical'),
			COUNT(*) FILTER (WHERE severity = 'high'),
			COUNT(*) FILTER (WHERE severity = 'medium'),
			COUNT(*) FILTER (WHERE severity = 'low')
		FROM alerts
		WHERE status <> 'resolved'`,
	).Scan(&c.Critical, &c.High, &c.Medium, &c.Low)
	if err != nil {
		return c, fmt.Errorf("storage: querying severity counts: %w", err)
	}
	return c, nil
}

func (s *Store) StatusCounts(ctx context.Context) (StatusCounts, error) {
	var c StatusCounts
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'new'),
			COUNT(*) FILTER (WHERE status = 'in_triage'),
			COUNT(*) FILTER (WHERE status = 'resolved')
		FROM alerts`,
	).Scan(&c.New, &c.InTriage, &c.Resolved)
	if err != nil {
		return c, fmt.Errorf("storage: querying status counts: %w", err)
	}
	return c, nil
}

// SLACompliance considers only resolved alerts (an open alert hasn't
// missed or met its SLA yet — it's just still running). Joins against
// sla_targets so changing a target in the config table is reflected
// immediately without a code change.
func (s *Store) SLACompliance(ctx context.Context) (SLACompliance, error) {
	var c SLACompliance
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE EXTRACT(EPOCH FROM (a.resolved_at - a.created_at)) / 60 <= t.target_minutes),
			COUNT(*) FILTER (WHERE EXTRACT(EPOCH FROM (a.resolved_at - a.created_at)) / 60 >  t.target_minutes)
		FROM alerts a
		JOIN sla_targets t ON t.severity = a.severity
		WHERE a.status = 'resolved' AND a.resolved_at IS NOT NULL`,
	).Scan(&c.Met, &c.Breached)
	if err != nil {
		return c, fmt.Errorf("storage: querying SLA compliance: %w", err)
	}
	total := c.Met + c.Breached
	if total > 0 {
		c.PercentMet = (float64(c.Met) / float64(total)) * 100
	}
	return c, nil
}

// OpenAlertsByCategory groups open (non-resolved) alerts by tag. An alert
// can carry multiple tags (see Alert.Tags); each tag it has contributes to
// that tag's count via UNNEST, so the total across categories can exceed
// the total alert count for multi-tagged alerts. Alerts with zero tags are
// grouped under "Untagged" so they aren't silently dropped from the chart.
func (s *Store) OpenAlertsByCategory(ctx context.Context, limit int) ([]CategoryCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(tag, ''), 'Untagged') AS category, COUNT(*) AS n
		FROM (
			SELECT UNNEST(tags) AS tag
			FROM alerts
			WHERE status <> 'resolved'
			UNION ALL
			SELECT NULL FROM alerts WHERE status <> 'resolved' AND cardinality(tags) = 0
		) t
		GROUP BY category
		ORDER BY n DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: querying category counts: %w", err)
	}
	defer rows.Close()

	var out []CategoryCount
	for rows.Next() {
		var c CategoryCount
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, fmt.Errorf("storage: scanning category row: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DetectionVolume returns one row per day for the last `days` days
// (including days with zero alerts, so the trend line doesn't show gaps
// as missing data points), oldest first.
func (s *Store) DetectionVolume(ctx context.Context, days int) ([]DailyCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d::date::text, COUNT(a.id)
		FROM generate_series(
			(CURRENT_DATE - ($1::int - 1)),
			CURRENT_DATE,
			'1 day'
		) AS d
		LEFT JOIN alerts a ON a.created_at::date = d::date
		GROUP BY d
		ORDER BY d`,
		days,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: querying detection volume: %w", err)
	}
	defer rows.Close()

	var out []DailyCount
	for rows.Next() {
		var c DailyCount
		if err := rows.Scan(&c.Date, &c.Count); err != nil {
			return nil, fmt.Errorf("storage: scanning detection volume row: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SourceVolumeByCategory returns one row per (day, category) for the last
// `days` days, using the source_categories mapping table to bucket the
// free-text source_feed column. A source_feed with no mapping row falls
// back to "Other" via COALESCE rather than being excluded, so adding a new
// feed in config.yaml without a matching migration row degrades to an
// "Other" bucket instead of silently vanishing from the chart.
func (s *Store) SourceVolumeByCategory(ctx context.Context, days int) ([]SourceVolumeDay, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.created_at::date::text AS day,
		       COALESCE(sc.category, 'Other') AS category,
		       COUNT(*) AS n
		FROM alerts a
		LEFT JOIN source_categories sc ON sc.source_feed = a.source_feed
		WHERE a.created_at >= CURRENT_DATE - ($1::int - 1)
		GROUP BY day, category
		ORDER BY day`,
		days,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: querying source volume: %w", err)
	}
	defer rows.Close()

	var out []SourceVolumeDay
	for rows.Next() {
		var c SourceVolumeDay
		if err := rows.Scan(&c.Date, &c.Category, &c.Count); err != nil {
			return nil, fmt.Errorf("storage: scanning source volume row: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// --- Users API (for auth) ---

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, created_at
		FROM users WHERE username = $1`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("storage: fetching user: %w", err)
	}
	return &u, nil
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, role, created_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, username, role, created_at`,
		username, passwordHash, role, time.Now().UTC(),
	).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("storage: creating user: %w", err)
	}
	u.PasswordHash = passwordHash
	return &u, nil
}

// --- Audit log API ---
//
// WriteAudit is intentionally fire-and-forget-tolerant from the caller's
// perspective (handlers log a failure but do not fail the request on audit
// write errors) since availability of the primary action should not depend
// on the audit subsystem. See internal/api/handlers_alerts.go and
// handlers_auth.go for call sites.

func (s *Store) WriteAudit(ctx context.Context, entry AuditEntry) error {
	var userID interface{}
	if entry.UserID != "" {
		userID = entry.UserID
	}
	var alertID interface{}
	if entry.AlertID != "" {
		alertID = entry.AlertID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (user_id, username, action, alert_id, ip_address, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, entry.Username, entry.Action, alertID, entry.IPAddress, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("storage: writing audit entry: %w", err)
	}
	return nil
}

// ListAudit returns the most recent audit entries, optionally filtered to
// a single alert (e.g. "who has viewed or acknowledged this alert").
func (s *Store) ListAudit(ctx context.Context, limit int, alertID string) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(user_id::text, ''), username, action, COALESCE(alert_id::text, ''), ip_address, created_at
		FROM audit_log
		WHERE ($2 = '' OR alert_id::text = $2)
		ORDER BY created_at DESC
		LIMIT $1`,
		limit, alertID,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: querying audit log: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.AlertID, &e.IPAddress, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("storage: scanning audit row: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// --- Graph snapshots API ---

func (s *Store) SaveGraphSnapshot(ctx context.Context, kind, severity string, payload []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO graph_snapshots (kind, severity, payload, created_at)
		VALUES ($1, $2, $3, $4)`,
		kind, severity, payload, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("storage: saving graph snapshot: %w", err)
	}
	return nil
}

func (s *Store) ListGraphSnapshots(ctx context.Context, kind string, limit int) ([]GraphSnapshot, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, kind, payload, severity, created_at
		FROM graph_snapshots
		WHERE kind = $1
		ORDER BY created_at DESC
		LIMIT $2`,
		kind, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: querying graph snapshots: %w", err)
	}
	defer rows.Close()

	var snapshots []GraphSnapshot
	for rows.Next() {
		var g GraphSnapshot
		if err := rows.Scan(&g.ID, &g.Kind, &g.Payload, &g.Severity, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("storage: scanning snapshot row: %w", err)
		}
		snapshots = append(snapshots, g)
	}
	return snapshots, rows.Err()
}
