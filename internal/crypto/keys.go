package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// X25519Keypair holds an X25519 private/public key pair.
type X25519Keypair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateKeypair creates a new random X25519 keypair.
func GenerateKeypair() (*X25519Keypair, error) {
	var kp X25519Keypair
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("computing public key: %w", err)
	}
	copy(kp.Public[:], pub)

	return &kp, nil
}

// LoadKeypair loads a keypair from raw 32-byte private key bytes.
func LoadKeypair(privateKey []byte) (*X25519Keypair, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(privateKey))
	}

	var kp X25519Keypair
	copy(kp.Private[:], privateKey)

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("computing public key: %w", err)
	}
	copy(kp.Public[:], pub)

	return &kp, nil
}

// DeriveKey derives a sub-key from a secret using HKDF-SHA256.
// info provides domain separation (e.g. "agent-secret", "provision-key").
func DeriveKey(secret []byte, salt string, info string) ([]byte, error) {
	h := hkdf.New(sha256.New, secret, []byte(salt), []byte(info))
	key := make([]byte, 32)
	if _, err := h.Read(key); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}
	return key, nil
}

// WrapKey wraps a DEK using AES-256-GCM with a wrapping key.
// Returns base64-encoded wrapped DEK.
func WrapKey(dek []byte, wrappingKey []byte) (string, error) {
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return "", fmt.Errorf("creating wrap cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating wrap GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating wrap nonce: %w", err)
	}

	// nonce || ciphertext+tag
	sealed := gcm.Seal(nonce, nonce, dek, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// UnwrapKey unwraps a DEK using AES-256-GCM with a wrapping key.
// Input is base64-encoded wrapped DEK from WrapKey.
func UnwrapKey(wrapped string, wrappingKey []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("base64 decode wrapped key: %w", err)
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("creating unwrap cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating unwrap GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("wrapped key too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	dek, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap failed: %w", err)
	}

	return dek, nil
}
