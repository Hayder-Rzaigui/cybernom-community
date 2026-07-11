// Package logger provides a single structured logger for the whole
// application, built on the standard library's log/slog so there is no
// external logging dependency to audit.
package logger

import (
	"log/slog"
	"os"
	"strings"
)

// New builds a JSON structured logger. In production this output is meant
// to be shipped to your SIEM/log aggregator, not read directly.
//
// level accepts: debug, info, warn, error (case-insensitive, defaults to info).
func New(level string, pretty bool) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: lvl,
		// ReplaceAttr scrubs common secret-shaped keys defensively, in case a
		// caller accidentally logs a struct containing one. This is a safety
		// net, not a substitute for not logging secrets in the first place.
		ReplaceAttr: scrubSensitive,
	}

	var handler slog.Handler
	if pretty {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

var sensitiveKeys = map[string]struct{}{
	"password":      {},
	"secret":        {},
	"token":         {},
	"authorization": {},
	"client_secret": {},
	"webhook_url":   {},
	"jwt":           {},
	"api_key":       {},
}

func scrubSensitive(groups []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	for sensitive := range sensitiveKeys {
		if strings.Contains(key, sensitive) {
			return slog.String(a.Key, "[REDACTED]")
		}
	}
	return a
}
