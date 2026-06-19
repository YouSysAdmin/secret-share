// Package env holds the Viper-backed config loader (Config) and the per-process
// Runtime handed to domain handlers.
package env

import (
	"errors"
	"fmt"
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
	return &c, nil
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
	return nil
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
