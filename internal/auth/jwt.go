// Package auth implements CyberNom's built-in authentication layer: bcrypt
// password hashing, JWT access/refresh tokens, and HTTP middleware that
// enforces authentication + role checks on protected routes.
//
// This exists specifically to close the "no authentication" gap present in
// both predecessor projects (Vigil365 and Threat-Intel-Nom-Nom), which
// relied entirely on network placement (localhost binding / firewall) for
// access control. CyberNom still recommends network isolation as
// defense-in-depth (see docs/THREAT_MODEL.md) but does not depend on it.
//
// The role model itself is edition-specific and lives in roles_community.go
// / roles_enterprise.go, gated by the `enterprise` build tag — everything
// else in this package is shared, unconditional core.
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Role is a granular authorization level. The set of valid Role values is
// edition-specific and defined in roles_community.go (build tag !enterprise)
// or roles_enterprise.go (build tag enterprise) — never here. Keeping Role
// itself in the shared, tag-free core means Claims, TokenIssuer, and the
// RequireRole/RequireRoles middleware never need to know which edition they
// were compiled into; only the *set of roles that exist* differs.
type Role string

// Claims is the JWT payload used for both access and refresh tokens.
// TokenType distinguishes the two so a refresh token can never be used
// directly as an access token even if presented to a protected endpoint.
//
// Username is embedded so authenticated handlers (notably audit logging on
// alert view/acknowledge) can attribute an action to a human-readable
// identity without an extra DB round-trip per request. It is denormalized
// data — if a user is later renamed, tokens issued before the rename carry
// the old username until they expire and are reissued via login/refresh.
// That's an acceptable tradeoff for an access token with a short TTL; see
// config.yaml.example's access_token_ttl.
type Claims struct {
	UserID    string `json:"uid"`
	Username  string `json:"username"`
	Role      Role   `json:"role"`
	TokenType string `json:"typ"` // "access" | "refresh"
	jwt.RegisteredClaims
}

// TokenIssuer signs and validates JWTs using a single HMAC-SHA256 key.
type TokenIssuer struct {
	signingKey      []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	issuer          string
}

func NewTokenIssuer(signingKey string, accessTTL, refreshTTL time.Duration) (*TokenIssuer, error) {
	if len(signingKey) < 32 {
		return nil, errors.New("signing key must be at least 32 bytes")
	}
	return &TokenIssuer{
		signingKey:      []byte(signingKey),
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
		issuer:          "cybernom",
	}, nil
}

func (t *TokenIssuer) IssueAccessToken(userID, username string, role Role) (string, error) {
	return t.issue(userID, username, role, "access", t.accessTokenTTL)
}

func (t *TokenIssuer) IssueRefreshToken(userID, username string, role Role) (string, error) {
	return t.issue(userID, username, role, "refresh", t.refreshTokenTTL)
}

func (t *TokenIssuer) issue(userID, username string, role Role, tokenType string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		Username:  username,
		Role:      role,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(t.signingKey)
}

// Verify parses and validates a token, explicitly pinning the signing
// method to HS256 to prevent algorithm-confusion attacks (e.g. a forged
// "alg: none" or RS256-with-public-key-as-HMAC-secret token).
func (t *TokenIssuer) Verify(tokenString, expectedType string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(tok *jwt.Token) (interface{}, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tok.Header["alg"])
		}
		return t.signingKey, nil
	}, jwt.WithIssuer(t.issuer), jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}
	if claims.TokenType != expectedType {
		return nil, fmt.Errorf("expected token type %q, got %q", expectedType, claims.TokenType)
	}
	return claims, nil
}
