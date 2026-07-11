//go:build !enterprise

package api

import (
	"github.com/hayderrzaigui/cybernom/internal/crypto"
	"github.com/hayderrzaigui/cybernom/internal/siem"
)

// editionState is empty in the Community build: there is no encrypted
// secrets vault and no SIEM forwarder to hold a reference to (both are
// Enterprise-only features — see ENTERPRISE.md sections 3-4). It still
// exists as a type, embedded as a zero-size field on Server, so router.go's
// struct definition doesn't need its own build tag.
type editionState struct{}

// SetSecretsVault mirrors the Enterprise signature exactly (see
// server_enterprise.go) so cmd/cybernom/main.go can call it unconditionally
// with no build-tag branching in main.go itself. setup_community.go always
// passes nil here — Community has nothing to encrypt that needs this vault
// — so this is a deliberate, silent no-op.
func (s *Server) SetSecretsVault(vault *crypto.SecretsVault) {}

// SetSIEMForwarder mirrors the Enterprise signature exactly (see
// server_enterprise.go). Community's siem.NewForwarder always returns a
// *siem.NoopForwarder satisfying the same siem.AlertForwarder interface, so
// this accepts it and ignores it, same as it would ignore nil.
func (s *Server) SetSIEMForwarder(forwarder siem.AlertForwarder) {}
