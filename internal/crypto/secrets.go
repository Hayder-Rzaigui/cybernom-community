// Package crypto implements AES-256-GCM encryption for sensitive data at rest.
// All integration keys, API tokens, and credentials are encrypted using a
// master key loaded from the environment at startup.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// NonceSize is the standard GCM nonce size (12 bytes).
	NonceSize = 12
)

// SecretsVault manages encryption/decryption of sensitive data using AES-256-GCM.
type SecretsVault struct {
	key []byte // 32 bytes for AES-256
}

// NewSecretsVault creates a vault from a 32-byte master key. If the key is
// empty or invalid length, returns an error; the caller MUST NOT continue
// if key initialization fails.
func NewSecretsVault(masterKey string) (*SecretsVault, error) {
	if masterKey == "" {
		return nil, errors.New("CYBERNOM_MASTER_ENCRYPTION_KEY not set; encrypted secrets cannot be managed")
	}

	// Expect base64-encoded 32-byte key (produces 44 chars in base64)
	decoded, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil {
		return nil, fmt.Errorf("CYBERNOM_MASTER_ENCRYPTION_KEY is not valid base64: %w", err)
	}

	if len(decoded) != 32 {
		return nil, fmt.Errorf("CYBERNOM_MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes; got %d", len(decoded))
	}

	return &SecretsVault{key: decoded}, nil
}

// EncryptedSecret is the persisted representation: base64-encoded ciphertext
// with embedded nonce. Stored as TEXT in PostgreSQL.
type EncryptedSecret string

// Encrypt takes plaintext data and returns it encrypted. Data is JSON-encoded
// before encryption to support arbitrary values.
func (v *SecretsVault) Encrypt(data interface{}) (EncryptedSecret, error) {
	// JSON-marshal the input
	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshaling data: %w", err)
	}

	// Create cipher
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	// Encrypt: nonce + ciphertext (gcm.Seal includes authentication tag)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Return base64-encoded result
	return EncryptedSecret(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// Decrypt reverses Encrypt, returning the original data.
func (v *SecretsVault) Decrypt(encrypted EncryptedSecret, dst interface{}) error {
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(string(encrypted))
	if err != nil {
		return fmt.Errorf("decoding base64: %w", err)
	}

	if len(ciphertext) < NonceSize {
		return errors.New("ciphertext too short")
	}

	// Extract nonce and actual ciphertext
	nonce := ciphertext[:NonceSize]
	actual := ciphertext[NonceSize:]

	// Create cipher
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, actual, nil)
	if err != nil {
		return fmt.Errorf("decryption failed (key mismatch or corrupted data): %w", err)
	}

	// Unmarshal JSON
	if err := json.Unmarshal(plaintext, dst); err != nil {
		return fmt.Errorf("unmarshaling decrypted data: %w", err)
	}

	return nil
}

// EncryptString is a convenience wrapper for encrypting a single string.
func (v *SecretsVault) EncryptString(s string) (EncryptedSecret, error) {
	return v.Encrypt(s)
}

// DecryptString is a convenience wrapper for decrypting to a single string.
func (v *SecretsVault) DecryptString(encrypted EncryptedSecret) (string, error) {
	var result string
	if err := v.Decrypt(encrypted, &result); err != nil {
		return "", err
	}
	return result, nil
}
