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

// TelegramChannel sends alerts via the Telegram Bot API's sendMessage
// endpoint. Unlike Discord/Slack, Telegram has no "incoming webhook URL"
// concept — it needs a bot token (from @BotFather) and a target chat ID
// (a user, group, or channel the bot has been added to). Both are read
// from environment variables at send time, following the same
// never-log/never-store-in-config pattern as DiscordChannel/SlackChannel.
type TelegramChannel struct {
	botTokenEnvVar string
	chatIDEnvVar   string
	httpClient     *http.Client
}

func NewTelegramChannel(botTokenEnvVar, chatIDEnvVar string) *TelegramChannel {
	return &TelegramChannel{
		botTokenEnvVar: botTokenEnvVar,
		chatIDEnvVar:   chatIDEnvVar,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *TelegramChannel) Name() string { return "telegram" }

var severityEmoji = map[string]string{
	"low":      "⚪",
	"medium":   "🟡",
	"high":     "🟠",
	"critical": "🔴",
}

func (c *TelegramChannel) Send(ctx context.Context, alert Alert) error {
	botToken := os.Getenv(c.botTokenEnvVar)
	if botToken == "" {
		return fmt.Errorf("telegram: bot token env var %q is not set", c.botTokenEnvVar)
	}
	chatID := os.Getenv(c.chatIDEnvVar)
	if chatID == "" {
		return fmt.Errorf("telegram: chat id env var %q is not set", c.chatIDEnvVar)
	}

	emoji := severityEmoji[alert.Severity]
	if emoji == "" {
		emoji = "⚪"
	}

	// Telegram's HTML parse mode only needs <, >, & escaped (a small,
	// fixed tag set — b/i/u/s/a/code/pre — is otherwise interpreted
	// literally). Feed-derived text (title, snippet, source name) is
	// adversarial by nature — especially from onion/dark-web sources —
	// so every field that isn't a URL we built ourselves must be
	// escaped before being interpolated into the message body.
	text := fmt.Sprintf(
		"%s <b>CyberNom Alert: %s</b>\n\n<b>Severity:</b> %s\n<b>Source:</b> %s\n<b>Article:</b> %s\n\n%s\n\n%s",
		emoji,
		telegramEscape(alert.KeywordName),
		strings.ToUpper(alert.Severity),
		telegramEscape(alert.SourceFeed),
		telegramEscape(truncate(alert.ItemTitle, 256)),
		telegramEscape(truncate(alert.Snippet, 1500)),
		telegramEscape(alert.ItemURL),
	)

	// Telegram's sendMessage caps text at 4096 UTF-16 code units; this is a
	// conservative byte-based approximation (bytes >= UTF-16 units for any
	// encoding).
	text = truncate(text, 4000)

	payload := map[string]interface{}{
		"chat_id":                  chatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram: marshaling payload: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram: sending message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram: api returned status %d", resp.StatusCode)
	}
	return nil
}

// telegramEscape escapes the three characters that are syntactically
// special in Telegram's HTML parse mode (<, >, &). This is different
// from Discord/Slack, which take plain text or their own markdown, so
// truncate() from discord.go is reused as-is but escaping is applied
// separately here rather than baked into truncate itself.
func telegramEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
