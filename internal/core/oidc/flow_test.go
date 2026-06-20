package oidc

import (
	"strings"
	"testing"
	"time"
)

func TestStateRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	in := StatePayload{State: "abc", Nonce: "def", CodeVerifier: "verifier123", Provider: "google"}
	cookie := signState(in, secret, time.Now().Add(time.Minute))

	out, err := verifyState(cookie, secret)
	if err != nil {
		t.Fatalf("verifyState: %v", err)
	}
	if out != in {
		t.Errorf("round trip mismatch: got %+v want %+v", out, in)
	}
}

func TestStateTamperRejected(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	cookie := signState(StatePayload{State: "s", Nonce: "n", CodeVerifier: "v", Provider: "google"}, secret, time.Now().Add(time.Minute))

	// Flip the provider field in the body; the HMAC must no longer match.
	tampered := strings.Replace(cookie, "google", "evilcorp", 1)
	if _, err := verifyState(tampered, secret); err == nil {
		t.Error("verifyState accepted a tampered provider field")
	}

	// Wrong secret -> bad signature.
	if _, err := verifyState(cookie, []byte("ffffffffffffffffffffffffffffffff")); err == nil {
		t.Error("verifyState accepted a cookie signed with a different secret")
	}
}

func TestStateExpired(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	cookie := signState(StatePayload{State: "s", Nonce: "n", CodeVerifier: "v", Provider: "google"}, secret, time.Now().Add(-time.Second))
	if _, err := verifyState(cookie, secret); err == nil {
		t.Error("verifyState accepted an expired cookie")
	}
}

func TestStateMalformed(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, err := verifyState("not.enough.parts", secret); err == nil {
		t.Error("verifyState accepted a malformed cookie")
	}
}
