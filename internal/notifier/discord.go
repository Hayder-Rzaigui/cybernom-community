package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// DiscordChannel sends alerts as Discord embeds via an incoming webhook URL.
// The webhook URL is read from an environment variable at send time — it is
// never logged and never stored in the config file (see config.go's
// NotificationChannel.WebhookEnvVar).
type DiscordChannel struct {
	webhookEnvVar string
	httpClient    *http.Client
}

func NewDiscordChannel(webhookEnvVar string) *DiscordChannel {
	return &DiscordChannel{
		webhookEnvVar: webhookEnvVar,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *DiscordChannel) Name() string { return "discord" }

var severityColor = map[string]int{
	"low":      0x8A8F98, // grey
	"medium":   0xF5A623, // amber
	"high":     0xE8590C, // orange
	"critical": 0xD32F2F, // red
}

func (c *DiscordChannel) Send(ctx context.Context, alert Alert) error {
	webhookURL := os.Getenv(c.webhookEnvVar)
	if webhookURL == "" {
		return fmt.Errorf("discord: webhook env var %q is not set", c.webhookEnvVar)
	}
	if !strings.HasPrefix(webhookURL, "https://discord.com/api/webhooks/") &&
		!strings.HasPrefix(webhookURL, "https://discordapp.com/api/webhooks/") {
		// Defensive check: refuses to POST alert content to a URL that
		// isn't actually a Discord webhook endpoint, in case the env var
		// was misconfigured (e.g. accidentally pointed at an internal URL).
		return fmt.Errorf("discord: configured URL does not look like a discord webhook endpoint")
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("🚨 CyberNom Alert: %s", alert.KeywordName),
				"description": truncate(alert.Snippet, 2000),
				"color":       severityColor[alert.Severity],
				"fields": []map[string]interface{}{
					{"name": "Severity", "value": strings.ToUpper(alert.Severity), "inline": true},
					{"name": "Source", "value": alert.SourceFeed, "inline": true},
					{"name": "Article", "value": truncate(alert.ItemTitle, 256), "inline": false},
					{"name": "Link", "value": alert.ItemURL, "inline": false},
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("discord: marshaling payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("discord: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("discord: sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("discord: webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// truncate shortens s to at most max bytes, appending an ellipsis. Feed
// content routinely contains multi-byte UTF-8 (Cyrillic, CJK, Arabic, etc,
// especially from onion/dark-web sources), so this must never cut in the
// middle of a rune — doing so produces invalid UTF-8, which downstream
// consumers (Discord/Slack's APIs, Postgres) can reject or mangle.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - 1
	if cut < 0 {
		cut = 0
	}
	// Walk back to the start of a rune: continuation bytes have the
	// high bits 10xxxxxx, so utf8.RuneStart(b) is false for them.
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
