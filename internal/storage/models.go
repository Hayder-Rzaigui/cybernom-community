// Package storage implements Postgres-backed persistence for users,
// alerts, feed state, and Graph collector snapshots.
package storage

import "time"

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"` // never serialized to JSON
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

type Alert struct {
	ID           string     `json:"id"`
	KeywordName  string     `json:"keyword_name"`
	Severity     string     `json:"severity"`
	SourceFeed   string     `json:"source_feed"`
	ItemTitle    string     `json:"item_title"`
	ItemURL      string     `json:"item_url"`
	Snippet      string     `json:"snippet"`
	Tags         []string   `json:"tags"`
	Acknowledged bool       `json:"acknowledged"`
	Status       string     `json:"status"`               // "new" | "in_triage" | "resolved"
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// SeverityCounts is the aggregate behind the "alerts by severity" donut.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// StatusCounts is the aggregate behind the "alerts by status" donut.
type StatusCounts struct {
	New      int `json:"new"`
	InTriage int `json:"in_triage"`
	Resolved int `json:"resolved"`
}

// SLACompliance is the aggregate behind the "SLA compliance" donut: of
// alerts resolved in the given window, how many were resolved within their
// severity's target (see sla_targets table) vs after it.
type SLACompliance struct {
	Met        int     `json:"met"`
	Breached   int     `json:"breached"`
	PercentMet float64 `json:"percent_met"`
}

// CategoryCount is one row of the "open alerts by category" bar list,
// derived from the alert's tags rather than a separate category field —
// see storage.OpenAlertsByCategory.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// DailyCount is one point on the "detection volume" trend line.
type DailyCount struct {
	Date  string `json:"date"` // YYYY-MM-DD
	Count int    `json:"count"`
}

// SourceVolumeDay is one (day, category) cell in the "log collection by
// source" stacked bar — category is the bucket from source_categories
// (Forums/Pastes/Telegram/Code hosts/Other), not the raw source_feed name.
type SourceVolumeDay struct {
	Date     string `json:"date"`
	Category string `json:"category"`
	Count    int    `json:"count"`
}

type GraphSnapshot struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"` // "security_alert" | "risky_signin"
	Payload   []byte    `json:"payload"` // raw JSON from Graph, for audit/detail view
	Severity  string    `json:"severity,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditEntry records a single access-relevant action for the audit trail:
// who (user + IP), what (action), and against which alert if applicable.
// Written on alert list/view, alert acknowledge, and login attempts.
type AuditEntry struct {
	ID        int64     `json:"id"`
	UserID    string    `json:"user_id,omitempty"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	AlertID   string    `json:"alert_id,omitempty"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
}
