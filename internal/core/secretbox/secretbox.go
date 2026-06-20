// Package secretbox seals small secrets at rest with AES-256-GCM. The key is
// derived from the session secret, so blobs in the DB (e.g. TOTP secrets) are
// useless on their own - which matters since the DB ends up in backups. Rotating
// auth.session_secret makes existing blobs undecryptable (users re-enroll 2FA),
// the same blast radius a rotation already has for cookies.
//
// This is unrelated to the zero-knowledge secret-sharing crypto (that happens in
// the browser and the server never holds those keys); it only protects the auth
// system's own at-rest material.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// DeriveKey turns an arbitrary-length secret into a 32-byte AES-256 key.
func DeriveKey(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

// Seal encrypts plaintext with key and returns base64(nonce || ciphertext+tag).
func Seal(key []byte, plaintext string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. It fails (non-nil error) on a wrong key or tampered input.
func Open(key []byte, b64 string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	return string(pt), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	return cipher.NewGCM(block)
}
