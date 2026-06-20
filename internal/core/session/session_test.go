package session

import (
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	in := Claims{Subject: "a@b.com", Email: "a@b.com", Name: "A", Role: "admin"}
	cookie, err := Sign(in, secret, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	out, err := Verify(cookie, secret)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Email != in.Email || out.Role != in.Role || out.Subject != in.Subject {
		t.Errorf("round trip mismatch: got %+v", out)
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	cookie, _ := Sign(Claims{Email: "a@b.com"}, []byte("0123456789abcdef0123456789abcdef"), time.Now().Add(time.Hour))
	if _, err := Verify(cookie, []byte("ffffffffffffffffffffffffffffffff")); err == nil {
		t.Error("Verify accepted a cookie signed with a different secret")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	cookie, _ := Sign(Claims{Email: "a@b.com"}, secret, time.Now().Add(-time.Second))
	if _, err := Verify(cookie, secret); err == nil {
		t.Error("Verify accepted an expired cookie")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, err := Verify("garbage", secret); err == nil {
		t.Error("Verify accepted a malformed cookie")
	}
}
