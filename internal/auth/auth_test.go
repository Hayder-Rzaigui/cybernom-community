package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hayderrzaigui/cybernom/internal/auth"
)

func TestTokenIssuer_RejectsShortSigningKey(t *testing.T) {
	_, err := auth.NewTokenIssuer("too-short", 15*time.Minute, time.Hour)
	if err == nil {
		t.Fatal("expected error for signing key under 32 bytes, got nil")
	}
}

func TestTokenIssuer_IssueAndVerifyAccessToken(t *testing.T) {
	issuer, err := auth.NewTokenIssuer(strings.Repeat("k", 32), 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("unexpected error creating issuer: %v", err)
	}

	token, err := issuer.IssueAccessToken("user-123", "alice", auth.RoleAdmin)
	if err != nil {
		t.Fatalf("unexpected error issuing token: %v", err)
	}

	claims, err := issuer.Verify(token, "access")
	if err != nil {
		t.Fatalf("expected valid access token to verify, got error: %v", err)
	}
	if claims.UserID != "user-123" || claims.Role != auth.RoleAdmin || claims.Username != "alice" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

// TestTokenIssuer_RefreshTokenRejectedAsAccessToken guards against a token
// confusion vulnerability: a caller must not be able to use a
// long-lived refresh token directly against an access-token-protected route.
func TestTokenIssuer_RefreshTokenRejectedAsAccessToken(t *testing.T) {
	issuer, _ := auth.NewTokenIssuer(strings.Repeat("k", 32), 15*time.Minute, time.Hour)

	refreshToken, err := issuer.IssueRefreshToken("user-123", "alice", auth.RoleViewer)
	if err != nil {
		t.Fatalf("unexpected error issuing refresh token: %v", err)
	}

	if _, err := issuer.Verify(refreshToken, "access"); err == nil {
		t.Fatal("expected refresh token to be rejected when verified as an access token")
	}

	// but it should verify fine as a refresh token
	if _, err := issuer.Verify(refreshToken, "refresh"); err != nil {
		t.Fatalf("expected refresh token to verify as refresh type, got error: %v", err)
	}
}

func TestTokenIssuer_RejectsTokenFromDifferentKey(t *testing.T) {
	issuerA, _ := auth.NewTokenIssuer(strings.Repeat("a", 32), 15*time.Minute, time.Hour)
	issuerB, _ := auth.NewTokenIssuer(strings.Repeat("b", 32), 15*time.Minute, time.Hour)

	token, _ := issuerA.IssueAccessToken("user-123", "alice", auth.RoleAdmin)

	if _, err := issuerB.Verify(token, "access"); err == nil {
		t.Fatal("expected token signed by a different key to fail verification")
	}
}

func TestPassword_HashAndVerifyRoundTrip(t *testing.T) {
	hash, err := auth.HashPassword("a-reasonably-long-password", 10)
	if err != nil {
		t.Fatalf("unexpected error hashing password: %v", err)
	}
	if err := auth.VerifyPassword(hash, "a-reasonably-long-password"); err != nil {
		t.Errorf("expected correct password to verify, got error: %v", err)
	}
	if err := auth.VerifyPassword(hash, "wrong-password"); err == nil {
		t.Error("expected incorrect password to fail verification")
	}
}

func TestPassword_RejectsShortPassword(t *testing.T) {
	_, err := auth.HashPassword("short", 10)
	if err == nil {
		t.Fatal("expected error for password under 12 characters, got nil")
	}
}
