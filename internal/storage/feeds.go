package storage

import (
	"context"
	"fmt"
	"time"
)

// ThreatFeed is a database-driven threat intelligence feed, replacing the
// static config.yaml Feed entries so operators can add/enable/disable
// feeds without a config change + restart. See migrations/0003_feeds.sql.
type ThreatFeed struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	FeedType      string     `json:"feed_type"` // rss | api | website | onion
	URL           string     `json:"url"`
	Enabled       bool       `json:"enabled"`
	PollInterval  string     `json:"poll_interval"` // Postgres interval, rendered as text (e.g. "06:00:00")
	Tags          []string   `json:"tags"`
	RequireTor    bool       `json:"require_tor"`
	APIMethod     string     `json:"api_method,omitempty"`
	APIAuthHeader string     `json:"api_auth_header,omitempty"`
	APIDataPath   string     `json:"api_data_path,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastPolledAt  *time.Time `json:"last_polled_at,omitempty"`
}

// FeedPollStat summarizes the most recent poll of a feed, for the
// "one-click feed management" admin UI's status column.
type FeedPollStat struct {
	FeedID       string    `json:"feed_id"`
	PolledAt     time.Time `json:"polled_at"`
	ItemCount    int       `json:"item_count"`
	AlertCount   int       `json:"alert_count"`
	ErrorMessage string    `json:"error_message,omitempty"`
	DurationMs   int       `json:"duration_ms"`
}

// --- Threat feeds API ---

func (s *Store) ListFeeds(ctx context.Context) ([]ThreatFeed, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, feed_type, url, enabled, poll_interval::text, tags,
		       require_tor, COALESCE(api_method, ''), COALESCE(api_auth_header, ''),
		       COALESCE(api_data_path, ''), created_at, updated_at, last_polled_at
		FROM threat_feeds
		ORDER BY name ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: querying threat feeds: %w", err)
	}
	defer rows.Close()

	var feeds []ThreatFeed
	for rows.Next() {
		var f ThreatFeed
		if err := rows.Scan(
			&f.ID, &f.Name, &f.FeedType, &f.URL, &f.Enabled, &f.PollInterval, &f.Tags,
			&f.RequireTor, &f.APIMethod, &f.APIAuthHeader, &f.APIDataPath,
			&f.CreatedAt, &f.UpdatedAt, &f.LastPolledAt,
		); err != nil {
			return nil, fmt.Errorf("storage: scanning threat feed row: %w", err)
		}
		feeds = append(feeds, f)
	}
	return feeds, rows.Err()
}

func (s *Store) GetFeed(ctx context.Context, id string) (*ThreatFeed, error) {
	var f ThreatFeed
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, feed_type, url, enabled, poll_interval::text, tags,
		       require_tor, COALESCE(api_method, ''), COALESCE(api_auth_header, ''),
		       COALESCE(api_data_path, ''), created_at, updated_at, last_polled_at
		FROM threat_feeds WHERE id = $1`,
		id,
	).Scan(
		&f.ID, &f.Name, &f.FeedType, &f.URL, &f.Enabled, &f.PollInterval, &f.Tags,
		&f.RequireTor, &f.APIMethod, &f.APIAuthHeader, &f.APIDataPath,
		&f.CreatedAt, &f.UpdatedAt, &f.LastPolledAt,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: fetching threat feed: %w", err)
	}
	return &f, nil
}

// CreateFeedParams groups the fields needed to insert a new feed, keeping
// CreateFeed's signature manageable as the schema grows.
type CreateFeedParams struct {
	Name          string
	FeedType      string
	URL           string
	PollInterval  time.Duration
	Tags          []string
	RequireTor    bool
	APIMethod     string
	APIAuthHeader string
	APIDataPath   string
}

func (s *Store) CreateFeed(ctx context.Context, p CreateFeedParams) (*ThreatFeed, error) {
	var f ThreatFeed
	err := s.pool.QueryRow(ctx, `
		INSERT INTO threat_feeds
			(name, feed_type, url, enabled, poll_interval, tags, require_tor,
			 api_method, api_auth_header, api_data_path)
		VALUES ($1, $2, $3, true, make_interval(secs => $4), $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''))
		RETURNING id, name, feed_type, url, enabled, poll_interval::text, tags,
		          require_tor, COALESCE(api_method, ''), COALESCE(api_auth_header, ''),
		          COALESCE(api_data_path, ''), created_at, updated_at, last_polled_at`,
		p.Name, p.FeedType, p.URL, p.PollInterval.Seconds(), p.Tags, p.RequireTor,
		p.APIMethod, p.APIAuthHeader, p.APIDataPath,
	).Scan(
		&f.ID, &f.Name, &f.FeedType, &f.URL, &f.Enabled, &f.PollInterval, &f.Tags,
		&f.RequireTor, &f.APIMethod, &f.APIAuthHeader, &f.APIDataPath,
		&f.CreatedAt, &f.UpdatedAt, &f.LastPolledAt,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: creating threat feed: %w", err)
	}
	return &f, nil
}

// SetFeedEnabled toggles a feed on/off in place — the core of "one-click
// feed management": no restart or config redeploy needed, the ingester
// engine is expected to poll this table and pick up the change on its next
// scheduling pass.
func (s *Store) SetFeedEnabled(ctx context.Context, id string, enabled bool) (*ThreatFeed, error) {
	var f ThreatFeed
	err := s.pool.QueryRow(ctx, `
		UPDATE threat_feeds SET enabled = $2, updated_at = now()
		WHERE id = $1
		RETURNING id, name, feed_type, url, enabled, poll_interval::text, tags,
		          require_tor, COALESCE(api_method, ''), COALESCE(api_auth_header, ''),
		          COALESCE(api_data_path, ''), created_at, updated_at, last_polled_at`,
		id, enabled,
	).Scan(
		&f.ID, &f.Name, &f.FeedType, &f.URL, &f.Enabled, &f.PollInterval, &f.Tags,
		&f.RequireTor, &f.APIMethod, &f.APIAuthHeader, &f.APIDataPath,
		&f.CreatedAt, &f.UpdatedAt, &f.LastPolledAt,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: toggling threat feed: %w", err)
	}
	return &f, nil
}

func (s *Store) DeleteFeed(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM threat_feeds WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("storage: deleting threat feed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: threat feed %s not found", id)
	}
	return nil
}

// FeedStats returns the single most recent poll record for a feed, used by
// the admin UI to show "last polled / item count / errors" per feed.
func (s *Store) FeedStats(ctx context.Context, feedID string) (*FeedPollStat, error) {
	var stat FeedPollStat
	err := s.pool.QueryRow(ctx, `
		SELECT feed_id, polled_at, item_count, alert_count, COALESCE(error_message, ''), COALESCE(duration_ms, 0)
		FROM feed_poll_history
		WHERE feed_id = $1
		ORDER BY polled_at DESC
		LIMIT 1`,
		feedID,
	).Scan(&stat.FeedID, &stat.PolledAt, &stat.ItemCount, &stat.AlertCount, &stat.ErrorMessage, &stat.DurationMs)
	if err != nil {
		return nil, fmt.Errorf("storage: fetching feed stats: %w", err)
	}
	return &stat, nil
}

// RecordFeedPoll appends a polling-history row for a feed and updates its
// last_polled_at timestamp. Called by the ingester engine after each poll
// cycle, success or failure (errMsg is empty on success).
func (s *Store) RecordFeedPoll(ctx context.Context, feedID string, itemCount, alertCount int, errMsg string, durationMs int) error {
	var errVal interface{}
	if errMsg != "" {
		errVal = errMsg
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_poll_history (feed_id, polled_at, item_count, alert_count, error_message, duration_ms)
		VALUES ($1, now(), $2, $3, $4, $5)`,
		feedID, itemCount, alertCount, errVal, durationMs,
	)
	if err != nil {
		return fmt.Errorf("storage: recording feed poll: %w", err)
	}
	_, err = s.pool.Exec(ctx, `UPDATE threat_feeds SET last_polled_at = now() WHERE id = $1`, feedID)
	if err != nil {
		return fmt.Errorf("storage: updating feed last_polled_at: %w", err)
	}
	return nil
}
