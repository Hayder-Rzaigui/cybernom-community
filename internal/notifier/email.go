package notifier

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gopkg.in/gomail.v2"
)

// EmailChannel sends alerts via SMTP. Credentials are read from an
// environment variable, never from config.yaml.
type EmailChannel struct {
	host           string
	port           int
	username       string
	passwordEnvVar string
	from           string
	to             []string
	useTLS         bool
}

func NewEmailChannel(host string, port int, username, passwordEnvVar, from string, to []string, useTLS bool) *EmailChannel {
	return &EmailChannel{
		host:           host,
		port:           port,
		username:       username,
		passwordEnvVar: passwordEnvVar,
		from:           from,
		to:             to,
		useTLS:         useTLS,
	}
}

func (c *EmailChannel) Name() string { return "email" }

func (c *EmailChannel) Send(ctx context.Context, alert Alert) error {
	password := os.Getenv(c.passwordEnvVar)
	if password == "" {
		return fmt.Errorf("email: password env var %q is not set", c.passwordEnvVar)
	}
	if len(c.to) == 0 {
		return fmt.Errorf("email: no recipients configured")
	}

	subject := fmt.Sprintf("[CyberNom][%s] %s", strings.ToUpper(alert.Severity), alert.KeywordName)
	bodyText := fmt.Sprintf(
		"Severity: %s\nSource feed: %s\nArticle: %s\nLink: %s\n\nMatched context:\n%s\n",
		strings.ToUpper(alert.Severity), alert.SourceFeed, alert.ItemTitle, alert.ItemURL, alert.Snippet,
	)

	m := gomail.NewMessage()
	m.SetHeader("From", c.from)
	m.SetHeader("To", c.to...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", bodyText)

	d := gomail.NewDialer(c.host, c.port, c.username, password)
	d.SSL = c.useTLS

	// gomail's DialAndSend is synchronous and doesn't accept a context
	// directly; we respect ctx cancellation by checking before dialing,
	// since SMTP transactions here are expected to be short-lived.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("email: sending via smtp: %w", err)
	}
	return nil
}
