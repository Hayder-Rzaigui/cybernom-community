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
)

// SlackChannel sends alerts via a Slack incoming webhook.
type SlackChannel struct {
	webhookEnvVar string
	httpClient    *http.Client
}

func NewSlackChannel(webhookEnvVar string) *SlackChannel {
	return &SlackChannel{
		webhookEnvVar: webhookEnvVar,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *SlackChannel) Name() string { return "slack" }

// escapeSlackMrkdwn escapes the characters Slack's mrkdwn format treats
// specially, per Slack's own escaping guidance, so untrusted feed content
// can't break message formatting or forge a masked link. Order matters:
// '&' must be escaped first, or the ampersands introduced while escaping
// '<'/'>' would themselves get re-escaped.
func escapeSlackMrkdwn(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func (c *SlackChannel) Send(ctx context.Context, alert Alert) error {
	webhookURL := os.Getenv(c.webhookEnvVar)
	if webhookURL == "" {
		return fmt.Errorf("slack: webhook env var %q is not set", c.webhookEnvVar)
	}
	if !strings.HasPrefix(webhookURL, "https://hooks.slack.com/") {
		return fmt.Errorf("slack: configured URL does not look like a slack webhook endpoint")
	}

	// KeywordName, SourceFeed, ItemTitle, ItemURL, and Snippet all ultimately
	// derive from external feed content (hostile input per the threat
	// model). Slack's mrkdwn gives '&', '<', and '>' special meaning ('<...>'
	// opens a link/mention, '&' starts an entity), so escape them per
	// Slack's own recommendation to stop a crafted feed item from breaking
	// message formatting or forging a masked link (e.g. "<https://evil|
	// looks-safe>").
	text := fmt.Sprintf(
		"*🚨 CyberNom Alert: %s*  `%s`\n*Source:* %s\n*Article:* %s\n*Link:* %s\n> %s",
		escapeSlackMrkdwn(alert.KeywordName),
		strings.ToUpper(alert.Severity),
		escapeSlackMrkdwn(alert.SourceFeed),
		escapeSlackMrkdwn(truncate(alert.ItemTitle, 256)),
		escapeSlackMrkdwn(alert.ItemURL),
		escapeSlackMrkdwn(truncate(alert.Snippet, 1500)),
	)

	payload := map[string]string{"text": text}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack: marshaling payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack: sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack: webhook returned status %d", resp.StatusCode)
	}
	return nil
}
