// Package notifier routes triggered alerts to one or more configured
// channels (Discord, Slack, email, generic webhook), filtering by minimum
// severity per channel.
package notifier

import (
	"context"
	"fmt"
	"log/slog"
)

var severityRank = map[string]int{
	"low":      0,
	"medium":   1,
	"high":     2,
	"critical": 3,
}

// Alert is the normalized payload every channel implementation receives.
type Alert struct {
	KeywordName string
	Severity    string
	Tags        []string
	SourceFeed  string
	ItemTitle   string
	ItemURL     string
	Snippet     string
}

// Channel is implemented by each notification sink.
type Channel interface {
	Name() string
	Send(ctx context.Context, alert Alert) error
}

// Router holds a set of channels each with a minimum severity threshold and
// fans out qualifying alerts to all of them concurrently-safely (Send is
// called sequentially per alert but channels are independent — a failure
// in one channel does not block or fail the others).
type Router struct {
	log      *slog.Logger
	channels []routedChannel
}

type routedChannel struct {
	channel     Channel
	minSeverity int
}

func NewRouter(log *slog.Logger) *Router {
	return &Router{log: log}
}

// Register adds a channel with a minimum severity filter (e.g. "high" means
// only high/critical alerts reach this channel).
func (r *Router) Register(ch Channel, minSeverity string) error {
	rank, ok := severityRank[minSeverity]
	if !ok {
		return fmt.Errorf("unknown severity %q for channel %q", minSeverity, ch.Name())
	}
	r.channels = append(r.channels, routedChannel{channel: ch, minSeverity: rank})
	return nil
}

// Dispatch sends the alert to every channel whose threshold it meets. Each
// channel's error is logged independently; Dispatch itself does not fail
// just because one downstream integration (e.g. a revoked webhook) is down.
func (r *Router) Dispatch(ctx context.Context, alert Alert) {
	alertRank, ok := severityRank[alert.Severity]
	if !ok {
		r.log.Warn("alert has unknown severity, defaulting to low", "severity", alert.Severity, "keyword", alert.KeywordName)
		alertRank = severityRank["low"]
	}

	for _, rc := range r.channels {
		if alertRank < rc.minSeverity {
			continue
		}
		if err := rc.channel.Send(ctx, alert); err != nil {
			r.log.Error("notification channel failed", "channel", rc.channel.Name(), "keyword", alert.KeywordName, "error", err)
			continue
		}
		r.log.Info("alert dispatched", "channel", rc.channel.Name(), "keyword", alert.KeywordName, "severity", alert.Severity)
	}
}
