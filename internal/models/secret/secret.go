// Package secret models a shared secret and its lifecycle.
// A secret is created with an expiry, retrieved exactly once,
// then burned. Every secret is zero-knowledge:
// the browser encrypts the plaintext and the key lives in the
// link fragment, so the server only ever holds opaque ciphertext.
package secret

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// Secret is one stored secret. ID is a random, unguessable, URL-safe token that
// doubles as the bearer capability for the ciphertext.
//
// NOTE: the bolt store serializes records with encoding/json, so the json tags
// are also the at-rest schema - Ciphertext must therefore be serialized (not json:"-").
// To keep it out of API responses, the meta/reveal handlers build their JSON by hand
// and NEVER marshal a *Secret directly to a client.
type Secret struct {
	ID string `json:"id"`

	// Ciphertext is the browser's AES-GCM output (base64); the server cannot
	// decrypt it. Emitted to the client only by the reveal/burn path (never meta).
	Ciphertext string `json:"ciphertext,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"` // the background sweeper purges on this field
	Size      int       `json:"size"`       // ciphertext byte length, for the meta endpoint
}

// IsExpired reports whether the secret's lifetime has elapsed as of now.
func (s *Secret) IsExpired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt)
}

// NewID returns a random, URL-safe, 144-bit identifier for a secret.
func NewID() (string, error) {
	buf := make([]byte, 18) // 18 bytes -> 144 bits -> 24 base64url chars
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
