// Package user models the identities that sign in when secret-share runs in
// private mode: the admins who manage the server and the regular users allowed to
// create (and, in "all" gate mode, reveal) secrets. The bbolt store lives in
// internal/domain/users; this package holds just the model + role constants
// so handlers, middleware, and the store don't import each other.
//
// Users are orthogonal to the zero-knowledge secret model: a user only
// gates *access* to the API, it never touches the opaque ciphertext a secret holds.
package user

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role is a user's access level. Two tiers: admin (everything, including
// user management) and user (may create/reveal secrets, but not manage others).
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleAdmin || r == RoleUser }

// Allows reports whether a user holding role r may act with the authority
// of want. admin satisfies every role; user satisfies only user.
func (r Role) Allows(want Role) bool {
	if r == RoleAdmin {
		return true
	}
	return r == want
}

// ParseRole normalizes s to a Role, defaulting to user for empty/unknown input
// and reporting whether the input was a recognized role.
func ParseRole(s string) (Role, bool) {
	switch Role(strings.ToLower(strings.TrimSpace(s))) {
	case RoleAdmin:
		return RoleAdmin, true
	case RoleUser:
		return RoleUser, true
	default:
		return RoleUser, false
	}
}

// Source records how a user authenticates.
const (
	SourceLocal = "local" // email + bcrypt password
	SourceOIDC  = "oidc"  // single sign-on; no local password
)

// User is one console identity. Email is the primary key (lowercased): an
// OIDC login matches a pre-seeded user by the same email, so a CLI-created
// local admin and the same person's OIDC account line up on one record.
type User struct {
	Email        string `json:"email"`
	Name         string `json:"name,omitempty"`
	Role         Role   `json:"role"`
	Source       string `json:"source"`
	PasswordHash string `json:"password_hash,omitempty"`
	// Pinned users (created by `user create`, or matched by an OIDC
	// provider's admin_emails) are always admin and are exempt from OIDC group
	// downgrade, so an IdP misconfiguration can't lock every admin out.
	Pinned  bool   `json:"pinned,omitempty"`
	Enabled bool   `json:"enabled"`
	Subject string `json:"subject,omitempty"` // OIDC sub, recorded on first SSO login

	// TOTP 2FA (local accounts only, opt-in). TOTPSecretEnc is the base32 shared
	// secret sealed at rest (see core/secretbox), written at enrollment;
	// TOTPEnabled flips true only once the user proves a code. RecoveryCodeHashes
	// are bcrypt hashes of one-time codes, consumed on use.
	TOTPEnabled        bool     `json:"totp_enabled,omitempty"`
	TOTPSecretEnc      string   `json:"totp_secret_enc,omitempty"`
	RecoveryCodeHashes []string `json:"recovery_code_hashes,omitempty"`

	// Passkeys (WebAuthn, local accounts only). WebAuthnHandle is the stable
	// random user handle the authenticator stores (generated on first passkey,
	// used to resolve passwordless logins back to this user). Passkeys is an
	// opaque JSON blob owned by the passkey layer, kept as raw bytes so this
	// package stays a leaf.
	WebAuthnHandle []byte          `json:"webauthn_handle,omitempty"`
	Passkeys       json.RawMessage `json:"passkeys,omitempty"`

	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// NormalizeEmail lowercases and trims an email for use as the store key.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// SetPassword bcrypt-hashes plain and stores it on the user. Callers must
// reject passwords longer than 72 bytes before this point (bcrypt's input limit).
func (p *User) SetPassword(plain string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	p.PasswordHash = string(h)
	return nil
}

// CheckPassword reports whether plain matches the stored bcrypt hash. False when
// no password is set (OIDC-only users can never password-login).
func (p *User) CheckPassword(plain string) bool {
	if p.PasswordHash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(p.PasswordHash), []byte(plain)) == nil
}

// dummyHash is a valid bcrypt hash with no known plaintext, computed once at
// startup, used only to equalize login timing.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("secret-share-dummy"), bcrypt.DefaultCost)

// FakePasswordCheck runs a throwaway bcrypt comparison and always returns false.
// Call it on the "no such local user" branch so a failed login costs the
// same whether or not the email exists (mitigates user enumeration via timing).
func FakePasswordCheck(plain string) bool {
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(plain))
	return false
}

// GenerateRecoveryCodes returns n random one-time codes formatted
// "xxxxx-xxxxx-xxxxx" (lowercase base32). Show them to the user ONCE, then store
// only their hashes via SetRecoveryCodes.
func GenerateRecoveryCodes(n int) ([]string, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 10) // 10 bytes -> 16 base32 chars; we use 15
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		s := strings.ToLower(enc.EncodeToString(buf))
		codes = append(codes, s[0:5]+"-"+s[5:10]+"-"+s[10:15])
	}
	return codes, nil
}

// normRecovery canonicalizes a recovery code for hashing/comparison: lowercase,
// no dashes or spaces - so the user can type it with or without the formatting.
func normRecovery(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// SetRecoveryCodes replaces the stored recovery codes with bcrypt hashes of the
// given plaintext codes.
func (p *User) SetRecoveryCodes(codes []string) error {
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		h, err := bcrypt.GenerateFromPassword([]byte(normRecovery(c)), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		hashes = append(hashes, string(h))
	}
	p.RecoveryCodeHashes = hashes
	return nil
}

// ConsumeRecoveryCode reports whether code matches an unused recovery code,
// removing it (one-time use) when it does. The caller must persist the user.
func (p *User) ConsumeRecoveryCode(code string) bool {
	norm := normRecovery(code)
	if norm == "" {
		return false
	}
	for i, h := range p.RecoveryCodeHashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(norm)) == nil {
			p.RecoveryCodeHashes = append(p.RecoveryCodeHashes[:i], p.RecoveryCodeHashes[i+1:]...)
			return true
		}
	}
	return false
}
