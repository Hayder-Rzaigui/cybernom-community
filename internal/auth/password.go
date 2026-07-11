package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a plaintext password with bcrypt at the configured cost.
// Cost is validated by config.Validate() to never be below 10.
func HashPassword(plaintext string, cost int) (string, error) {
	if len(plaintext) < 12 {
		return "", fmt.Errorf("password must be at least 12 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), cost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword performs a constant-time comparison of a plaintext password
// against a stored bcrypt hash. Returns nil on match.
func VerifyPassword(hash, plaintext string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}
