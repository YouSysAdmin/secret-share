// Package oidc wires the SSO login flow: issuer discovery, authorization-code
// redirect with PKCE, ID-token verification on callback, admission, and role
// mapping (see Admit and RoleFor). It supports multiple providers via Registry,
// each rendering one button on the login page.
//
// State, nonce, the PKCE verifier, and the provider id ride the round-trip in a
// short-lived HMAC-signed cookie - no server-side state.
package oidc

import (
	"context"
	"fmt"
	"net/url"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	// ID is the stable, URL-safe provider key used in the callback path and the
	// state-cookie binding. Label is the login button text.
	ID    string
	Label string

	Issuer               string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	Scopes               []string
	RequireEmailVerified bool
	AllowedDomains       []string
	AllowedEmails        []string
	GroupsClaim          string

	// Role mapping (see RoleFor). All lists are lowercased/trimmed by config
	// validation. AdminEmails also pin a user to admin, and the
	// AdminGroups+UserGroups union doubles as the group admission allowlist
	// (there is no separate allowed_groups).
	AdminEmails []string
	AdminGroups []string
	UserGroups  []string
	DefaultRole string
}

// StateCookie carries state+nonce+verifier+provider across the IdP round-trip.
// Cleared on callback success or failure.
const StateCookie = "share_oidc_state"

const StateCookieTTL = 10 * time.Minute

// Provider bundles the IdP discovery result, an oauth2.Config, and an ID-token
// verifier. Build once at startup and reuse across requests.
type Provider struct {
	cfg      Config
	oauth2   *oauth2.Config
	verifier *gooidc.IDTokenVerifier
}

func New(ctx context.Context, cfg Config) (*Provider, error) {
	prov, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery (%s): %w", cfg.Issuer, err)
	}
	return &Provider{
		cfg: cfg,
		oauth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     prov.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		verifier: prov.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

func (p *Provider) Config() Config { return p.cfg }
func (p *Provider) ID() string     { return p.cfg.ID }

func (p *Provider) Label() string {
	if p.cfg.Label != "" {
		return p.cfg.Label
	}
	return p.IssuerHost()
}

func (p *Provider) IssuerHost() string {
	u, err := url.Parse(p.cfg.Issuer)
	if err != nil || u.Host == "" {
		return p.cfg.Issuer
	}
	return u.Host
}
