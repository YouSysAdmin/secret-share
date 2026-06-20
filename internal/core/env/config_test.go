package env

import "testing"

// validBase returns a Config that passes the non-auth parts of Validate, so each
// test can focus on the auth block.
func validBase() *Config {
	return &Config{
		Secrets: SecretsConfig{
			MaxSizeBytes: 65536,
			MaxTTL:       "168h",
			DefaultTTL:   "24h",
			AllowedTTLs:  []string{"24h"},
		},
	}
}

const goodSecret = "0123456789abcdef0123456789abcdef" // 32 chars

func TestValidate_AuthDisabledIgnoresAuthFields(t *testing.T) {
	c := validBase()
	c.Auth = AuthConfig{Enabled: false, SessionSecret: "short", Gate: "bogus"}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled auth should skip auth validation: %v", err)
	}
}

func TestValidate_SessionSecretRequired(t *testing.T) {
	c := validBase()
	c.Auth = AuthConfig{Enabled: true, LocalLogin: true, SessionSecret: "tooshort"}
	if err := c.Validate(); err == nil {
		t.Fatal("want error for short session_secret")
	}
}

func TestValidate_GateNormalizedAndChecked(t *testing.T) {
	c := validBase()
	c.Auth = AuthConfig{Enabled: true, LocalLogin: true, SessionSecret: goodSecret, Gate: ""}
	if err := c.Validate(); err != nil {
		t.Fatalf("empty gate should normalize: %v", err)
	}
	if c.Auth.Gate != "create" {
		t.Errorf("empty gate should normalize to create, got %q", c.Auth.Gate)
	}

	c = validBase()
	c.Auth = AuthConfig{Enabled: true, LocalLogin: true, SessionSecret: goodSecret, Gate: "everything"}
	if err := c.Validate(); err == nil {
		t.Fatal("want error for invalid gate")
	}
}

func TestValidate_NoSignInMethod(t *testing.T) {
	c := validBase()
	c.Auth = AuthConfig{Enabled: true, LocalLogin: false, SessionSecret: goodSecret}
	if err := c.Validate(); err == nil {
		t.Fatal("want error when local_login is off and no OIDC providers exist")
	}
}

func TestValidate_BootstrapPasswordBounds(t *testing.T) {
	c := validBase()
	long := make([]byte, 73)
	for i := range long {
		long[i] = 'a'
	}
	c.Auth = AuthConfig{
		Enabled: true, LocalLogin: true, SessionSecret: goodSecret,
		BootstrapAdmin: BootstrapAdminConfig{Email: "a@b.com", Password: string(long)},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("want error for bootstrap password over 72 bytes")
	}
}

func goodProvider() OIDCProviderConfig {
	return OIDCProviderConfig{
		ID:           "google",
		Issuer:       "https://accounts.google.com",
		ClientID:     "cid",
		ClientSecret: "secret",
		RedirectURL:  "https://app.example.com/api/auth/oidc/google/callback",
	}
}

func TestValidate_OIDCValid(t *testing.T) {
	c := validBase()
	p := goodProvider()
	p.AdminEmails = []string{"BOSS@Acme.com"}
	c.Auth = AuthConfig{Enabled: true, SessionSecret: goodSecret, OIDC: []OIDCProviderConfig{p}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid OIDC provider rejected: %v", err)
	}
	got := c.Auth.OIDC[0]
	if got.Label != "google" {
		t.Errorf("label should default to id, got %q", got.Label)
	}
	if len(got.Scopes) == 0 {
		t.Error("scopes should default to openid/email/profile")
	}
	if got.AdminEmails[0] != "boss@acme.com" {
		t.Errorf("admin_emails should be lowercased, got %q", got.AdminEmails[0])
	}
}

func TestValidate_OIDCErrors(t *testing.T) {
	cases := map[string]func(p *OIDCProviderConfig){
		"missing id":          func(p *OIDCProviderConfig) { p.ID = "" },
		"bad id chars":        func(p *OIDCProviderConfig) { p.ID = "Google!" },
		"non-https issuer":    func(p *OIDCProviderConfig) { p.Issuer = "http://accounts.google.com" },
		"missing client_id":   func(p *OIDCProviderConfig) { p.ClientID = "" },
		"bad redirect suffix": func(p *OIDCProviderConfig) { p.RedirectURL = "https://app.example.com/cb" },
		"groups need claim":   func(p *OIDCProviderConfig) { p.AdminGroups = []string{"admins"} },
		"bad default_role":    func(p *OIDCProviderConfig) { p.DefaultRole = "superuser" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := validBase()
			p := goodProvider()
			mut(&p)
			c.Auth = AuthConfig{Enabled: true, SessionSecret: goodSecret, OIDC: []OIDCProviderConfig{p}}
			if err := c.Validate(); err == nil {
				t.Errorf("want error for %q", name)
			}
		})
	}
}

func TestValidate_OIDCDuplicateID(t *testing.T) {
	c := validBase()
	c.Auth = AuthConfig{
		Enabled: true, SessionSecret: goodSecret,
		OIDC: []OIDCProviderConfig{goodProvider(), goodProvider()},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("want error for duplicate provider id")
	}
}

// applyOIDCEnvOverrides: per-field env overrides keyed by provider id, the
// hybrid "config in file, secret via env" case.
func TestApplyOIDCEnvOverrides(t *testing.T) {
	// File-defined provider with everything but the secret.
	p := OIDCProviderConfig{
		ID:          "google",
		Issuer:      "https://accounts.google.com",
		ClientID:    "gid",
		RedirectURL: "https://app.example.com/api/auth/oidc/google/callback",
		Scopes:      []string{"openid", "email"},
	}
	t.Setenv("SHARE_AUTH_OIDC_GOOGLE_CLIENT_SECRET", "from-env")
	applyOIDCEnvOverrides(&p)

	if p.ClientSecret != "from-env" {
		t.Errorf("client_secret should come from env, got %q", p.ClientSecret)
	}
	// Untouched fields keep their file values.
	if p.ClientID != "gid" || p.Issuer != "https://accounts.google.com" {
		t.Errorf("non-overridden fields changed: %+v", p)
	}
	if len(p.Scopes) != 2 {
		t.Errorf("scopes should be untouched, got %v", p.Scopes)
	}
}

// Env-only mode: SHARE_AUTH_OIDC_PROVIDERS builds the whole list, and ids map to
// the right env infix (dash -> underscore).
func TestEnvOnlyProvidersViaLoad(t *testing.T) {
	t.Setenv("SHARE_AUTH_OIDC_PROVIDERS", "google, azure-ad")
	t.Setenv("SHARE_AUTH_OIDC_GOOGLE_ISSUER", "https://accounts.google.com")
	t.Setenv("SHARE_AUTH_OIDC_GOOGLE_CLIENT_ID", "gid")
	t.Setenv("SHARE_AUTH_OIDC_GOOGLE_CLIENT_SECRET", "gsecret")
	t.Setenv("SHARE_AUTH_OIDC_GOOGLE_REDIRECT_URL", "https://app.example.com/api/auth/oidc/google/callback")
	t.Setenv("SHARE_AUTH_OIDC_GOOGLE_ALLOWED_DOMAINS", "acme.com, sub.acme.com")
	t.Setenv("SHARE_AUTH_OIDC_GOOGLE_REQUIRE_EMAIL_VERIFIED", "false")
	// id "azure-ad" -> infix AZURE_AD
	t.Setenv("SHARE_AUTH_OIDC_AZURE_AD_ISSUER", "https://login.microsoftonline.com/t/v2.0")
	t.Setenv("SHARE_AUTH_OIDC_AZURE_AD_CLIENT_ID", "eid")
	t.Setenv("SHARE_AUTH_OIDC_AZURE_AD_CLIENT_SECRET", "esecret")
	t.Setenv("SHARE_AUTH_OIDC_AZURE_AD_REDIRECT_URL", "https://app.example.com/api/auth/oidc/azure-ad/callback")

	// Empty path -> looks for ./secret-share.yaml (absent in the test dir), which
	// Load tolerates, so providers come purely from env.
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Auth.OIDC) != 2 {
		t.Fatalf("want 2 providers, got %d", len(c.Auth.OIDC))
	}
	g := c.Auth.OIDC[0]
	if g.ID != "google" || g.ClientSecret != "gsecret" || len(g.AllowedDomains) != 2 {
		t.Errorf("google mis-parsed: %+v", g)
	}
	if g.RequireEmailVerified == nil || *g.RequireEmailVerified {
		t.Errorf("require_email_verified should be false pointer, got %v", g.RequireEmailVerified)
	}
	az := c.Auth.OIDC[1]
	if az.ID != "azure-ad" || az.Issuer == "" || az.ClientSecret != "esecret" {
		t.Errorf("azure-ad mis-parsed (infix mapping?): %+v", az)
	}
}
