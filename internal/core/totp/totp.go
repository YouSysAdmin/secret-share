// Package totp wraps github.com/pquerna/otp for self-service 2FA: enrolling a
// per-user shared secret (with a QR code for authenticator apps) and validating
// submitted 6-digit codes with a small clock skew. It is used only for local
// (password) accounts; OIDC accounts get MFA from their IdP.
package totp

import (
	"bytes"
	"encoding/base64"
	"image/png"

	"github.com/pquerna/otp/totp"
)

// Issuer is the label shown in the authenticator app (the "issuer" of the
// otpauth:// URI), grouping all this server's accounts together.
const Issuer = "secret-share"

// Enrollment is what the UI needs to set up an authenticator: the raw base32
// Secret (for manual entry) plus a ready-to-render QR PNG of the otpauth:// URI.
type Enrollment struct {
	Secret      string // base32 shared secret - store ENCRYPTED, never expose after enrollment
	URL         string // otpauth://totp/... provisioning URI
	QRPNGBase64 string // PNG of URL, for <img src="data:image/png;base64,...">
}

// Enroll generates a fresh secret for account (the user's email) and renders its
// QR code. The caller persists Secret encrypted (see secretbox) and only marks
// 2FA enabled once the user proves possession via Validate.
func Enroll(account string) (*Enrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: Issuer, AccountName: account})
	if err != nil {
		return nil, err
	}
	img, err := key.Image(220, 220)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return &Enrollment{
		Secret:      key.Secret(),
		URL:         key.String(),
		QRPNGBase64: base64.StdEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

// Validate reports whether code is currently valid for secret. pquerna's default
// allows a ±1 period (30s) skew to tolerate clock drift.
func Validate(code, secret string) bool {
	return totp.Validate(code, secret)
}
