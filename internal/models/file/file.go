// Package file models a shared encrypted file. Like a secret, a file is
// created with an expiry, retrieved exactly once, then burned - and it is
// zero-knowledge: the browser encrypts the filename and content together into
// one opaque blob, and the key never reaches the server.
package file

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// File is one stored encrypted file. ID is a random, unguessable, URL-safe
// token that doubles as the bearer capability for the ciphertext.
//
// NOTE: the bolt store serializes records with encoding/json, so the json tags
// are also the at-rest schema (Ciphertext must not be json:"-"; []byte
// round-trips as base64). Handlers never marshal *File to a client - meta is
// built by hand and reveal streams the raw bytes.
type File struct {
	ID string `json:"id"`

	// Ciphertext is the browser's AES-GCM output over (header || content); the
	// server cannot decrypt it. Sent to the client only by the reveal/burn path.
	Ciphertext []byte `json:"ciphertext,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"` // the background sweeper purges on this field
	Size      int       `json:"size"`       // ciphertext byte length, for the meta endpoint
}

// IsExpired reports whether the file's lifetime has elapsed as of now.
func (f *File) IsExpired(now time.Time) bool {
	return !f.ExpiresAt.IsZero() && now.After(f.ExpiresAt)
}

// NewID returns a random, URL-safe, 144-bit identifier for a file.
func NewID() (string, error) {
	buf := make([]byte, 18) // 18 bytes -> 144 bits -> 24 base64url chars
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
