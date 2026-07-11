// Package siem implements automatic forwarding of verified alerts to
// external SIEM platforms via Syslog (RFC 5424) and custom webhooks
// (Splunk, Sentinel).
//
// SIEM forwarding is an Enterprise Edition feature (ENTERPRISE.md section
// 3). This file holds the parts that must be visible regardless of build
// tag: AlertPayload (so internal/storage can construct one without caring
// which edition it's linked against) and the AlertForwarder interface (so
// internal/storage depends on a shape, not a concrete enterprise-only
// type). The two implementations of that interface — the real forwarder
// and the Community no-op — live in forwarder_enterprise.go and
// forwarder_community.go, split by the `enterprise` build tag.
package siem

import "time"

// AlertPayload is the SIEM package's own view of an alert to forward,
// deliberately independent of internal/storage.Alert so this package has
// no dependency on the storage package (storage, in turn, holds a
// reference to an AlertForwarder to dispatch newly-created alerts — an
// import cycle would result if this package imported storage directly).
type AlertPayload struct {
	ID           string
	KeywordName  string
	Severity     string
	SourceFeed   string
	ItemTitle    string
	ItemURL      string
	Snippet      string
	Tags         []string
	Acknowledged bool
	Status       string
	CreatedAt    time.Time
}

// ForwarderConfig configures SIEM integrations.
type ForwarderConfig struct {
	Syslog  *SyslogConfig  `json:"syslog,omitempty"`
	Webhook *WebhookConfig `json:"webhook,omitempty"`
}

// SyslogConfig configures RFC 5424 syslog forwarding.
type SyslogConfig struct {
	Enabled string // "tcp" | "udp" | "unix" | ""
	Address string // e.g., "siem.example.com:514" or "/var/run/syslog"
}

// WebhookConfig configures HTTP webhook forwarding (Splunk, Sentinel, etc.).
type WebhookConfig struct {
	Enabled string // "splunk" | "sentinel" | "generic" | ""
	URL     string // Webhook endpoint
	Token   string // Authorization token (from environment)
}

// AlertForwarder is the seam between internal/storage (which decides *when*
// to forward, on every newly verified alert) and the SIEM package (which
// decides *how*, and whether the feature exists at all in this build).
//
//   - Enterprise builds wire in *Forwarder (forwarder_enterprise.go), which
//     actually dials syslog/webhook endpoints.
//   - Community builds wire in *NoopForwarder (forwarder_community.go),
//     whose ForwardAlert is a deliberate no-op.
//
// storage.Store depends only on this interface, never on *Forwarder
// directly, so it compiles identically in both editions.
type AlertForwarder interface {
	// ForwardAlert sends an alert to configured SIEM endpoints. Must never
	// block ingestion on a slow/unreachable SIEM and must be safe to call
	// on a nil receiver (storage.Store treats "no forwarder configured"
	// and "forwarder is a nil interface value" the same way).
	ForwardAlert(alert *AlertPayload)
	// Close releases any held connections (e.g. a long-lived syslog
	// socket). Safe to call on a nil receiver.
	Close()
}

// severity3164 converts CyberNom severity to RFC 3164 syslog level (0-7).
// Shared because it's pure data mapping with no edition-specific behavior;
// kept here rather than duplicated in forwarder_enterprise.go.
func severity3164(sev string) int {
	switch sev {
	case "critical":
		return 2 // crit
	case "high":
		return 3 // err
	case "medium":
		return 4 // warning
	case "low":
		return 5 // notice
	default:
		return 6 // info
	}
}
