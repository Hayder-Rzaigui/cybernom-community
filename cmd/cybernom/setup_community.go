//go:build !enterprise

package main

import (
	"log/slog"

	"github.com/hayderrzaigui/cybernom/internal/crypto"
	"github.com/hayderrzaigui/cybernom/internal/siem"
)

// setupSecurityExtensions is the Community build's equivalent of
// setup_enterprise.go. Neither the encrypted secrets vault nor SIEM
// forwarding exist as features in Community (ENTERPRISE.md sections 3-4),
// so this deliberately does not read CYBERNOM_MASTER_ENCRYPTION_KEY or any
// CYBERNOM_SIEM_* environment variable, and never fails startup because of
// them — a Community deployment shouldn't need to think about Enterprise-only
// configuration at all.
//
// The returned vault is nil: Community's Server.SetSecretsVault is a no-op
// that accepts nil (or anything) without complaint. siem.NewForwarder in
// this build always returns a *siem.NoopForwarder, which logs a single
// informational line if it notices SIEM env vars set anyway (see
// forwarder_community.go), then does nothing on every ForwardAlert call.
func setupSecurityExtensions(log *slog.Logger) (*crypto.SecretsVault, siem.AlertForwarder, error) {
	noopForwarder, err := siem.NewForwarder(log, siem.ForwarderConfig{})
	if err != nil {
		// NewForwarder's Community implementation never actually returns
		// an error, but the signature must match the Enterprise version,
		// so this is handled defensively rather than assumed away.
		return nil, nil, err
	}
	return nil, noopForwarder, nil
}
