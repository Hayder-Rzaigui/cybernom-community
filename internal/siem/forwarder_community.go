//go:build !enterprise

package siem

import "log/slog"

// NoopForwarder is the Community Edition stand-in for the real Enterprise
// Forwarder. SIEM forwarding (ENTERPRISE.md section 3) is an Enterprise
// feature; a Community build still needs *something* satisfying
// AlertForwarder so internal/storage.Store can hold one unconditionally.
// This just does nothing, deliberately and quietly — SIEM env vars being
// present in a Community deployment's environment is not an error, they're
// simply ignored.
type NoopForwarder struct {
	log *slog.Logger
}

// compile-time assertion that *NoopForwarder satisfies AlertForwarder.
var _ AlertForwarder = (*NoopForwarder)(nil)

// NewForwarder mirrors the Enterprise constructor's signature exactly, so
// cmd/cybernom/main.go can call siem.NewForwarder(log, cfg) unconditionally
// with no build-tag branching in main.go itself — which implementation gets
// linked in is decided entirely by the `enterprise` build tag, at compile
// time, via Go's package system rather than a runtime switch.
//
// If any SIEM env var is actually set, this logs one informational line so
// an operator who configured SIEM forwarding and is running the Community
// binary isn't left wondering why alerts never show up in their SIEM —
// without that, "which binary am I running" would be a genuinely
// hard-to-debug question if it also matched the naming failure mode of
// silently returning a valid-looking forwarder that never forwarded.
func NewForwarder(log *slog.Logger, cfg ForwarderConfig) (*NoopForwarder, error) {
	if (cfg.Syslog != nil && cfg.Syslog.Enabled != "") || (cfg.Webhook != nil && cfg.Webhook.Enabled != "") {
		log.Info("siem: forwarding configuration detected but this is the Community build; SIEM forwarding is an Enterprise feature and will be ignored (see ENTERPRISE.md)")
	}
	return &NoopForwarder{log: log}, nil
}

// ForwardAlert is a deliberate no-op.
func (f *NoopForwarder) ForwardAlert(alert *AlertPayload) {}

// Close is a deliberate no-op.
func (f *NoopForwarder) Close() {}
