// Package env holds the Viper-backed config loader (Config) and the per-process
// Runtime handed to domain handlers.
package env

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"github.com/YouSysAdmin/secret-share/internal/core/tlsutils"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Secrets  SecretsConfig  `mapstructure:"secrets"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Logging  LoggingConfig  `mapstructure:"logging"`
}

type ServerConfig struct {
	Addr string `mapstructure:"addr"`

	// TrustedProxies lists the proxy IPs/CIDRs allowed to set X-Forwarded-* so
	// c.IP()/c.Protocol() reflect the real client. Empty -> trust none.
	TrustedProxies []string `mapstructure:"trusted_proxies"`

	// BehindTLSProxy says an external proxy terminates TLS in front of this server
	// (which then listens plain). It makes the app emit HSTS on its own plain hop,
	// since the client<->proxy hop is the encrypted one. Leave server.tls.mode at
	// "none" in this setup.
	BehindTLSProxy bool `mapstructure:"behind_tls_proxy"`

	// TLS lets the server terminate TLS itself (none | manual | self | acme).
	// Default "none": serve plain HTTP, e.g. behind a TLS-terminating proxy.
	TLS tlsutils.Config `mapstructure:"tls"`
}

// DatabaseConfig is the bbolt store config (single embedded file).
type DatabaseConfig struct {
	// Path is the bbolt file location. Default "secret-share.db".
	Path string `mapstructure:"path"`
	// SweepInterval is how often expired secrets are purged (a background sweeper
	// does it). Default "1m".
	SweepInterval string `mapstructure:"sweep_interval"`
}

// SecretsConfig governs secret storage limits and the lifetime options.
type SecretsConfig struct {
	// MaxSizeBytes caps the stored ciphertext per secret. Default 65536.
	MaxSizeBytes int `mapstructure:"max_size_bytes"`
	// MaxTTL is the ceiling on a requested lifetime. Default 168h.
	MaxTTL string `mapstructure:"max_ttl"`
	// DefaultTTL is the lifetime used when none is requested. Default 24h.
	DefaultTTL string `mapstructure:"default_ttl"`
	// AllowedTTLs are the preset lifetime options surfaced to the UI (Go durations).
	AllowedTTLs []string `mapstructure:"allowed_ttls"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
	Color  bool   `mapstructure:"color"`
}

// AuthConfig turns on "private mode": authentication in front of the API. Default
// zero value (Enabled=false) preserves the fully-open public behavior. Auth is an
// orthogonal access gate over still-opaque ciphertext - the zero-knowledge model
// is untouched.
type AuthConfig struct {
	// Enabled gates the API behind a login. Default false (public).
	Enabled bool `mapstructure:"enabled"`
	// Gate selects which routes require a session when Enabled:
	//   "create" - only POST /api/secrets (creating) requires login; meta+reveal
	//              stay public so external recipients can open a link.
	//   "all"    - create, meta, and reveal all require login (fully internal).
	// Default "create".
	Gate string `mapstructure:"gate"`
	// SessionSecret keys the HMAC session cookie and the at-rest secretbox seal.
	// Required (>=32 chars) when Enabled. Rotating it invalidates all sessions and
	// makes stored TOTP secrets undecryptable (users re-enroll 2FA).
	SessionSecret string `mapstructure:"session_secret"`
	// SessionTTL is the session cookie lifetime (Go duration). Default "12h".
	SessionTTL string `mapstructure:"session_ttl"`
	// LocalLogin allows email+password (and passkey) sign-in. Default true. Set
	// false to force OIDC-only.
	LocalLogin bool `mapstructure:"local_login"`
	// BootstrapAdmin, if set, seeds a pinned admin on first boot (idempotent).
	BootstrapAdmin BootstrapAdminConfig `mapstructure:"bootstrap_admin"`
	// OIDC is the list of SSO providers; each renders a button on the login page.
	// File-configured only (Viper cannot cleanly bind a struct slice from env).
	OIDC []OIDCProviderConfig `mapstructure:"oidc"`
}

// BootstrapAdminConfig seeds the first admin so the server is reachable before any
// CLI user is created. Password must be 8-72 bytes (bcrypt input limit).
type BootstrapAdminConfig struct {
	Email    string `mapstructure:"email"`
	Password string `mapstructure:"password"`
}

// OIDCProviderConfig is one SSO provider. Issuer must be a real OIDC issuer (with
// a /.well-known/openid-configuration discovery document). GitHub is OAuth2-only
// and is NOT supported here.
type OIDCProviderConfig struct {
	// ID is a stable, URL-safe, unique key used in the callback path and the
	// state cookie binding (e.g. "google", "entra").
	ID    string `mapstructure:"id"`
	Label string `mapstructure:"label"` // login button text; defaults to ID
	// Issuer/ClientID/ClientSecret/RedirectURL are the OAuth2/OIDC essentials.
	// RedirectURL must end with /api/auth/oidc/<id>/callback.
	Issuer       string   `mapstructure:"issuer"`
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURL  string   `mapstructure:"redirect_url"`
	Scopes       []string `mapstructure:"scopes"` // default ["openid","email","profile"]
	// RequireEmailVerified rejects logins whose email_verified claim is false.
	// Pointer so an unset value can default to true.
	RequireEmailVerified *bool `mapstructure:"require_email_verified"`
	// Admission lists (any match admits). When none are set, every authenticated
	// user from this IdP is admitted.
	AllowedDomains []string `mapstructure:"allowed_domains"`
	AllowedEmails  []string `mapstructure:"allowed_emails"`
	GroupsClaim    string   `mapstructure:"groups_claim"`
	// Role mapping. admin_emails pin a user to admin; the admin/user group
	// union also doubles as the group allowlist. default_role ("" or "none" means
	// deny when no other rule matches).
	AdminEmails []string `mapstructure:"admin_emails"`
	AdminGroups []string `mapstructure:"admin_groups"`
	UserGroups  []string `mapstructure:"user_groups"`
	DefaultRole string   `mapstructure:"default_role"`
}

// configKeys is the explicit env-bind list. AutomaticEnv only resolves a key on
// Get, but Unmarshal builds the struct from keys Viper already knows (config
// file + defaults + explicit binds). A key set only in the env (SHARE_*) won't
// reach the struct without an explicit bind, so bind every key here.
var configKeys = []string{
	"server.addr",
	"server.trusted_proxies",
	"server.behind_tls_proxy",
	"server.tls.mode",
	"server.tls.cert",
	"server.tls.key",
	"server.tls.fqdn",
	"server.tls.alg",
	"server.tls.acme.email",
	"server.tls.acme.cache_dir",
	"server.tls.acme.http_addr",
	"server.tls.acme.hosts",
	"database.path",
	"database.sweep_interval",
	"secrets.max_size_bytes",
	"secrets.max_ttl",
	"secrets.default_ttl",
	"secrets.allowed_ttls",
	// Auth scalar keys. The OIDC provider list (auth.oidc) is a struct slice
	// Viper can't BindEnv; it's loaded separately from SHARE_AUTH_OIDC_PROVIDERS +
	// SHARE_AUTH_OIDC_<ID>_* (see oidcProvidersFromEnv) or from the config file.
	"auth.enabled",
	"auth.gate",
	"auth.session_secret",
	"auth.session_ttl",
	"auth.local_login",
	"auth.bootstrap_admin.email",
	"auth.bootstrap_admin.password",
	"logging.level",
	"logging.format",
	"logging.output",
	"logging.color",
}

// Load reads YAML at path (or ./secret-share.yaml when empty), merges
// SHARE_*-prefixed env overrides, and returns the resolved Config.
func Load(path string) (*Config, error) {
	v := viper.New()
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.AddConfigPath(".")
		v.SetConfigName("secret-share")
		v.SetConfigType("yaml")
	}
	v.SetEnvPrefix("SHARE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	for _, key := range configKeys {
		_ = v.BindEnv(key)
	}

	v.SetDefault("server.addr", ":3000")
	v.SetDefault("database.path", "secret-share.db")
	v.SetDefault("database.sweep_interval", "1m")
	v.SetDefault("secrets.max_size_bytes", 65536)
	v.SetDefault("secrets.max_ttl", "168h")
	v.SetDefault("secrets.default_ttl", "24h")
	v.SetDefault("secrets.allowed_ttls", []string{"5m", "1h", "24h", "168h"})
	v.SetDefault("auth.enabled", false)
	v.SetDefault("auth.gate", "create")
	v.SetDefault("auth.session_ttl", "12h")
	v.SetDefault("auth.local_login", true)
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var c Config
	// Env values arrive as strings; WeaklyTypedInput coerces them to bools/ints
	// (Viper's default hooks already handle slices/durations).
	if err := v.Unmarshal(&c, func(dc *mapstructure.DecoderConfig) {
		dc.WeaklyTypedInput = true
	}); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// OIDC providers can't be Viper-bound from env (struct slice), so resolve them
	// from SHARE_AUTH_OIDC_* here:
	//   - SHARE_AUTH_OIDC_PROVIDERS set -> build the whole list from env (no file).
	//   - otherwise -> keep the file's providers but let per-field env vars override
	//     each (keyed by provider id), so you can keep config in the file and inject
	//     just the secret via SHARE_AUTH_OIDC_<ID>_CLIENT_SECRET.
	if ids := splitCommaList(os.Getenv("SHARE_AUTH_OIDC_PROVIDERS")); len(ids) > 0 {
		providers := make([]OIDCProviderConfig, 0, len(ids))
		for _, id := range ids {
			p := OIDCProviderConfig{ID: id}
			applyOIDCEnvOverrides(&p)
			providers = append(providers, p)
		}
		c.Auth.OIDC = providers
	} else {
		for i := range c.Auth.OIDC {
			applyOIDCEnvOverrides(&c.Auth.OIDC[i])
		}
	}
	return &c, nil
}

// applyOIDCEnvOverrides overlays SHARE_AUTH_OIDC_<ID>_* env vars onto p, where
// <ID> is the provider id uppercased with '-' replaced by '_' (id "azure-ad" ->
// SHARE_AUTH_OIDC_AZURE_AD_*). Each var overrides the corresponding field only
// when set and non-empty, so file config stays the default and env supplies the
// bits you don't want in the file (typically CLIENT_SECRET).
func applyOIDCEnvOverrides(p *OIDCProviderConfig) {
	pfx := "SHARE_AUTH_OIDC_" + envInfix(p.ID) + "_"
	p.Label = envStr(p.Label, pfx+"LABEL")
	p.Issuer = envStr(p.Issuer, pfx+"ISSUER")
	p.ClientID = envStr(p.ClientID, pfx+"CLIENT_ID")
	p.ClientSecret = envStr(p.ClientSecret, pfx+"CLIENT_SECRET")
	p.RedirectURL = envStr(p.RedirectURL, pfx+"REDIRECT_URL")
	p.GroupsClaim = envStr(p.GroupsClaim, pfx+"GROUPS_CLAIM")
	p.DefaultRole = envStr(p.DefaultRole, pfx+"DEFAULT_ROLE")
	p.Scopes = envList(p.Scopes, pfx+"SCOPES")
	p.AllowedDomains = envList(p.AllowedDomains, pfx+"ALLOWED_DOMAINS")
	p.AllowedEmails = envList(p.AllowedEmails, pfx+"ALLOWED_EMAILS")
	p.AdminEmails = envList(p.AdminEmails, pfx+"ADMIN_EMAILS")
	p.AdminGroups = envList(p.AdminGroups, pfx+"ADMIN_GROUPS")
	p.UserGroups = envList(p.UserGroups, pfx+"USER_GROUPS")
	if raw, ok := os.LookupEnv(pfx + "REQUIRE_EMAIL_VERIFIED"); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(raw)); err == nil {
			p.RequireEmailVerified = &b
		}
	}
}

// envStr returns the env value at key when set and non-empty, else cur.
func envStr(cur, key string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return cur
}

// envList returns the comma-split env value at key when set and non-empty, else cur.
func envList(cur []string, key string) []string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return splitCommaList(v)
	}
	return cur
}

// envInfix maps a provider id to its env-var infix: uppercased, '-' -> '_'.
func envInfix(id string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(id), "-", "_"))
}

// splitCommaList splits a comma-separated env value, trimming and dropping empties.
func splitCommaList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) Validate() error {
	// TLS: validate the mode + required fields at boot (no side effects). The
	// server's New() builds the actual *tls.Config once it starts.
	if err := tlsutils.ValidateConfig(c.Server.TLS); err != nil {
		return err
	}

	if c.Database.SweepInterval != "" {
		if d, err := time.ParseDuration(c.Database.SweepInterval); err != nil || d <= 0 {
			return fmt.Errorf("database.sweep_interval %q invalid: want a positive Go duration like 1m", c.Database.SweepInterval)
		}
	}

	if c.Secrets.MaxSizeBytes <= 0 {
		c.Secrets.MaxSizeBytes = 65536
	}
	maxTTL, err := parseRequiredDuration("secrets.max_ttl", c.Secrets.MaxTTL)
	if err != nil {
		return err
	}
	defTTL, err := parseRequiredDuration("secrets.default_ttl", c.Secrets.DefaultTTL)
	if err != nil {
		return err
	}
	if defTTL > maxTTL {
		return fmt.Errorf("secrets.default_ttl (%s) must not exceed secrets.max_ttl (%s)", defTTL, maxTTL)
	}
	for _, t := range c.Secrets.AllowedTTLs {
		d, err := time.ParseDuration(t)
		if err != nil || d <= 0 {
			return fmt.Errorf("secrets.allowed_ttls entry %q invalid: want a positive Go duration like 1h", t)
		}
		if d > maxTTL {
			return fmt.Errorf("secrets.allowed_ttls entry %q exceeds secrets.max_ttl (%s)", t, maxTTL)
		}
	}

	if err := c.validateAuth(); err != nil {
		return err
	}
	return nil
}

// validateAuth checks the auth (private mode) config. A no-op when auth is
// disabled. Mutates c to normalize the gate and lowercase the OIDC match lists.
func (c *Config) validateAuth() error {
	a := &c.Auth
	if !a.Enabled {
		return nil
	}

	switch strings.ToLower(strings.TrimSpace(a.Gate)) {
	case "", "create":
		a.Gate = "create"
	case "all":
		a.Gate = "all"
	default:
		return fmt.Errorf("auth.gate %q invalid: want \"create\" or \"all\"", a.Gate)
	}

	if len(a.SessionSecret) < 32 {
		return fmt.Errorf("auth.session_secret must be at least 32 characters when auth is enabled")
	}
	if a.SessionTTL != "" {
		if d, err := time.ParseDuration(a.SessionTTL); err != nil || d <= 0 {
			return fmt.Errorf("auth.session_ttl %q invalid: want a positive Go duration like 12h", a.SessionTTL)
		}
	}

	if a.BootstrapAdmin.Password != "" {
		if n := len(a.BootstrapAdmin.Password); n < 8 || n > 72 {
			return fmt.Errorf("auth.bootstrap_admin.password must be 8-72 bytes (got %d)", n)
		}
		if a.BootstrapAdmin.Email == "" {
			return fmt.Errorf("auth.bootstrap_admin.password set without auth.bootstrap_admin.email")
		}
	}

	seen := make(map[string]bool, len(a.OIDC))
	for i := range a.OIDC {
		if err := validateOIDCProvider(&a.OIDC[i], seen); err != nil {
			return err
		}
	}

	if len(a.OIDC) == 0 && !a.LocalLogin {
		return fmt.Errorf("auth.enabled is true but local_login is false and no OIDC providers are configured: no way to sign in")
	}
	return nil
}

// oidcIDPattern restricts a provider id to URL-safe characters (used in the
// callback path and the state-cookie binding).
var oidcIDPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

func validateOIDCProvider(p *OIDCProviderConfig, seen map[string]bool) error {
	p.ID = strings.TrimSpace(p.ID)
	if p.ID == "" {
		return fmt.Errorf("auth.oidc: every provider needs an id")
	}
	if !oidcIDPattern.MatchString(p.ID) {
		return fmt.Errorf("auth.oidc provider id %q invalid: use only lowercase letters, digits, '-' and '_'", p.ID)
	}
	if seen[p.ID] {
		return fmt.Errorf("auth.oidc provider id %q is duplicated", p.ID)
	}
	seen[p.ID] = true

	if p.Label == "" {
		p.Label = p.ID
	}
	if err := validateHTTPSURL("auth.oidc."+p.ID+".issuer", p.Issuer); err != nil {
		return err
	}
	if p.ClientID == "" {
		return fmt.Errorf("auth.oidc.%s.client_id is required", p.ID)
	}
	if p.ClientSecret == "" {
		return fmt.Errorf("auth.oidc.%s.client_secret is required", p.ID)
	}
	if err := validateHTTPSURL("auth.oidc."+p.ID+".redirect_url", p.RedirectURL); err != nil {
		return err
	}
	if want := "/api/auth/oidc/" + p.ID + "/callback"; !strings.HasSuffix(strings.TrimRight(p.RedirectURL, "/"), want) {
		return fmt.Errorf("auth.oidc.%s.redirect_url must end with %q", p.ID, want)
	}
	if len(p.Scopes) == 0 {
		p.Scopes = []string{"openid", "email", "profile"}
	}
	if (len(p.AdminGroups) > 0 || len(p.UserGroups) > 0) && strings.TrimSpace(p.GroupsClaim) == "" {
		return fmt.Errorf("auth.oidc.%s sets admin_groups/user_groups but no groups_claim", p.ID)
	}
	switch role := strings.ToLower(strings.TrimSpace(p.DefaultRole)); role {
	case "", "none", "admin", "user":
		p.DefaultRole = role
	default:
		return fmt.Errorf("auth.oidc.%s.default_role %q invalid: want \"\", \"none\", \"admin\" or \"user\"", p.ID, p.DefaultRole)
	}

	// Normalize the match lists so comparisons at login are case-insensitive.
	p.AllowedDomains = lowerTrimAll(p.AllowedDomains)
	p.AllowedEmails = lowerTrimAll(p.AllowedEmails)
	p.AdminEmails = lowerTrimAll(p.AdminEmails)
	p.AdminGroups = lowerTrimAll(p.AdminGroups)
	p.UserGroups = lowerTrimAll(p.UserGroups)
	p.GroupsClaim = strings.TrimSpace(p.GroupsClaim)
	return nil
}

func validateHTTPSURL(field, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s is required", field)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s %q invalid: want an absolute https URL", field, raw)
	}
	return nil
}

func lowerTrimAll(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// MaxTTLDuration returns the secret lifetime ceiling (default 168h).
func (c *Config) MaxTTLDuration() time.Duration { return mustDur(c.Secrets.MaxTTL, 168*time.Hour) }

// DefaultTTLDuration returns the default secret lifetime (default 24h).
func (c *Config) DefaultTTLDuration() time.Duration {
	return mustDur(c.Secrets.DefaultTTL, 24*time.Hour)
}

// SweepIntervalDuration returns the expired-secret sweep cadence (default 1m).
func (c *Config) SweepIntervalDuration() time.Duration {
	return mustDur(c.Database.SweepInterval, time.Minute)
}

// SessionTTLDuration returns the auth session lifetime (default 12h).
func (c *Config) SessionTTLDuration() time.Duration {
	return mustDur(c.Auth.SessionTTL, 12*time.Hour)
}

func parseRequiredDuration(field, raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s %q invalid: want a positive Go duration like 24h", field, raw)
	}
	return d, nil
}

func mustDur(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
