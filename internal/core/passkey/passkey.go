// Package passkey wraps go-webauthn for passwordless sign-in (WebAuthn / FIDO2).
// Local accounts only; with OIDC, sign-in is the IdP's job.
//
// The relying party is built per-request from the browser's Origin, so passkeys
// work in dev (localhost) and prod without static config and without relying on
// the front proxy preserving the Host header.
package passkey

import (
	"bytes"
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const displayName = "secret-share"

// Re-exported so callers (and the user storage) don't import go-webauthn
// directly.
type (
	Credential          = webauthn.Credential
	SessionData         = webauthn.SessionData
	CredentialCreation  = protocol.CredentialCreation
	CredentialAssertion = protocol.CredentialAssertion
)

// Stored is one persisted passkey: the credential plus display metadata. The
// user keeps a list of these as opaque JSON.
type Stored struct {
	Credential Credential `json:"credential"`
	Name       string     `json:"name"`
	AddedAt    string     `json:"added_at"`
}

// Decode/Encode (un)marshal the user's opaque passkey blob.
func Decode(raw []byte) ([]Stored, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []Stored
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func Encode(list []Stored) ([]byte, error) { return json.Marshal(list) }

// Credentials extracts the webauthn credentials from a stored list.
func Credentials(list []Stored) []Credential {
	creds := make([]Credential, 0, len(list))
	for i := range list {
		creds = append(creds, list[i].Credential)
	}
	return creds
}

// Service is a relying party bound to one (rpID, origin).
type Service struct{ wa *webauthn.WebAuthn }

// New builds the RP for rpID (the host, no scheme/port) and origin (the exact
// scheme://host[:port] the browser used).
func New(rpID, origin string) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     []string{origin},
	})
	if err != nil {
		return nil, err
	}
	return &Service{wa: wa}, nil
}

// User adapts a console identity to webauthn.User.
type User struct {
	Handle  []byte
	Name    string // email
	Display string // display name (falls back to Name)
	Creds   []Credential
}

func (u *User) WebAuthnID() []byte   { return u.Handle }
func (u *User) WebAuthnName() string { return u.Name }
func (u *User) WebAuthnDisplayName() string {
	if u.Display != "" {
		return u.Display
	}
	return u.Name
}
func (u *User) WebAuthnCredentials() []Credential { return u.Creds }

// BeginRegistration starts enrollment of a new discoverable (resident) passkey,
// excluding existing credentials so the same authenticator isn't registered
// twice. User verification is REQUIRED: a passkey signs in on its own, so it
// must be backed by a biometric/PIN (possession + verification = 2FA in one
// step), not mere presence. The library only enforces UV when it's required.
func (s *Service) BeginRegistration(u *User) (*CredentialCreation, *SessionData, error) {
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.Creds))
	for i := range u.Creds {
		exclude = append(exclude, u.Creds[i].Descriptor())
	}
	return s.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude),
	)
}

// FinishRegistration verifies the attestation in body and returns the new credential.
func (s *Service) FinishRegistration(u *User, sess SessionData, body []byte) (*Credential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return s.wa.CreateCredential(u, sess, parsed)
}

// BeginLogin starts a usernameless (discoverable) assertion - the browser shows
// the passkey picker, no email needed. User verification is REQUIRED to match
// registration: the library only checks the UV flag when the ceremony asked for
// it, so without this a login would prove possession (a tap) but not
// verification - too weak for a single-factor passwordless flow.
func (s *Service) BeginLogin() (*CredentialAssertion, *SessionData, error) {
	return s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
}

// FinishLogin verifies the assertion in body. resolve maps the authenticator's
// (rawID, userHandle) to the owning User; the matched *User is returned with the
// validated credential so the caller can mint a session and update the sign
// count. resolve is a plain func (not webauthn.User) so callers avoid importing
// go-webauthn.
func (s *Service) FinishLogin(resolve func(rawID, userHandle []byte) (*User, error), sess SessionData, body []byte) (*Credential, *User, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	var matched *User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := resolve(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		matched = u
		return u, nil
	}
	cred, err := s.wa.ValidateDiscoverableLogin(handler, sess, parsed)
	return cred, matched, err
}
