package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/logger"
	paoidc "github.com/YouSysAdmin/secret-share/internal/core/oidc"
	"github.com/YouSysAdmin/secret-share/internal/domain/files"
	"github.com/YouSysAdmin/secret-share/internal/domain/secrets"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
	"github.com/YouSysAdmin/secret-share/internal/server"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the secret-share server",
		RunE:  runServe,
	}
}

func runServe(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")

	cfg, err := env.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	log, err := logger.InitLogger(cfg.Logging.Level, cfg.Logging.Output, cfg.Logging.Format, cfg.Logging.Color)
	if err != nil {
		return err
	}
	if !cfg.Auth.Enabled {
		log.Warn("auth is DISABLED (public mode): anyone who can reach the server can create secrets")
	}
	if cfg.Server.BehindTLSProxy && len(cfg.Server.TrustedProxies) == 0 {
		log.Warn("server.behind_tls_proxy is set but server.trusted_proxies is empty: " +
			"list the TLS terminator in trusted_proxies so the real client IP and scheme are honored")
	}

	rt := &env.Runtime{
		Config:        cfg,
		Log:           log,
		ConfigPath:    absPath(cfgPath),
		SessionSecret: []byte(cfg.Auth.SessionSecret),
		SessionTTL:    cfg.SessionTTLDuration(),
	}

	// Build the OIDC provider registry (discovery runs once, fail-fast on a bad
	// or unreachable issuer).
	if cfg.Auth.Enabled && len(cfg.Auth.OIDC) > 0 {
		reg, err := buildOIDCRegistry(cfg, log)
		if err != nil {
			return fmt.Errorf("oidc: %w", err)
		}
		rt.OIDC = reg
	}

	st, closeStore, err := openStore(rt)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer closeStore()
	log.Info("storage ready", "path", rt.StoreProvider.Path())

	// Seed the first admin from auth.bootstrap_admin when configured, then refuse
	// to start with auth enabled and no way for an admin to exist. Runs in-process
	// against the open store, so it can't deadlock on the bbolt lock.
	if err := seedBootstrapAdmin(rt, st); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	if err := ensureBootstrapAdmin(rt, st); err != nil {
		return err
	}

	// Background sweeper purges expired secrets (bbolt has no TTL index).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secrets.StartSweeper(ctx, st, cfg.SweepIntervalDuration(), log)
	if cfg.Files.Enabled {
		files.StartSweeper(ctx, st, cfg.SweepIntervalDuration(), log)
	}
	// Drop visibility records left behind by private secrets that expired without
	// being revealed (a revealed secret drops its own record on burn).
	startVisibilitySweeper(ctx, st, cfg.SweepIntervalDuration(), log)
	// Same cleanup for multi-view budgets whose secret expired before the views
	// were used up (a fully consumed budget deletes its own record).
	startViewsSweeper(ctx, st, cfg.SweepIntervalDuration(), log)

	srv, err := server.New(server.Options{Runtime: rt, Store: st})
	if err != nil {
		return err
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Info("shutting down")
		cancel()
		if err := srv.Shutdown(); err != nil {
			log.Error("shutdown error", "err", err)
		}
	}()

	if err := srv.Start(); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

// seedBootstrapAdmin creates the first admin from auth.bootstrap_admin
// (SHARE_AUTH_BOOTSTRAP_ADMIN_EMAIL/_PASSWORD) when auth is enabled and no
// user with that email exists yet. Idempotent: an existing user is left
// untouched (no password reset on restart). A no-op when auth is disabled or the
// email is unset.
func seedBootstrapAdmin(rt *env.Runtime, st *store.Store) error {
	cfg := rt.Config
	if !cfg.Auth.Enabled {
		return nil
	}
	email := user.NormalizeEmail(cfg.Auth.BootstrapAdmin.Email)
	if email == "" {
		return nil
	}
	existing, err := st.Users.Get(context.Background(), email)
	if err != nil {
		return fmt.Errorf("lookup user %q: %w", email, err)
	}
	if existing != nil {
		return nil
	}
	p := &user.User{Email: email, Role: user.RoleAdmin, Pinned: true, Enabled: true}
	if cfg.Auth.BootstrapAdmin.Password != "" {
		if err := p.SetPassword(cfg.Auth.BootstrapAdmin.Password); err != nil {
			return fmt.Errorf("hash bootstrap password: %w", err)
		}
		p.Source = user.SourceLocal
	} else {
		// No password: identity comes from the IdP; pin admin to this email.
		p.Source = user.SourceOIDC
	}
	if err := st.Users.Upsert(context.Background(), p); err != nil {
		return fmt.Errorf("save bootstrap admin: %w", err)
	}
	rt.Log.Info("auth: seeded bootstrap admin from environment", "email", email, "source", p.Source)
	return nil
}

// ensureBootstrapAdmin refuses to start with auth enabled and no admin user,
// UNLESS OIDC is configured (an OIDC user mapped to admin can arrive on first
// login). A no-op when auth is disabled.
func ensureBootstrapAdmin(rt *env.Runtime, st *store.Store) error {
	cfg := rt.Config
	if !cfg.Auth.Enabled {
		return nil
	}
	n, err := st.Users.CountByRole(context.Background(), user.RoleAdmin)
	if err != nil {
		return fmt.Errorf("check admin users: %w", err)
	}
	if n > 0 {
		return nil
	}
	if len(cfg.Auth.OIDC) > 0 {
		rt.Log.Warn("auth: no admin user exists yet; an OIDC user mapped to admin " +
			"(admin_emails/admin_groups) will be created on first login")
		return nil
	}
	return fmt.Errorf("auth is enabled but no admin user exists: seed one via " +
		"SHARE_AUTH_BOOTSTRAP_ADMIN_EMAIL/_PASSWORD, or run `secret-share user create` " +
		"before starting the server")
}

// startVisibilitySweeper periodically drops visibility records whose secret is
// gone (expired or burned), so the visibility bucket can't grow without bound.
func startVisibilitySweeper(ctx context.Context, st *store.Store, interval time.Duration, log *slog.Logger) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ids, err := st.Visibility.List(ctx)
				if err != nil {
					log.Warn("visibility sweep: list failed", "err", err)
					continue
				}
				dropped := 0
				for _, id := range ids {
					s, err := st.Secrets.GetMeta(ctx, id)
					if err != nil {
						continue
					}
					if s == nil {
						if err := st.Visibility.Delete(ctx, id); err == nil {
							dropped++
						}
					}
				}
				if dropped > 0 {
					log.Debug("visibility sweep: dropped orphan records", "count", dropped)
				}
			}
		}
	}()
}

// startViewsSweeper periodically drops multi-view budget records whose secret
// is gone (expired or burned), so the views bucket can't grow without bound.
func startViewsSweeper(ctx context.Context, st *store.Store, interval time.Duration, log *slog.Logger) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ids, err := st.Views.List(ctx)
				if err != nil {
					log.Warn("views sweep: list failed", "err", err)
					continue
				}
				dropped := 0
				for _, id := range ids {
					s, err := st.Secrets.GetMeta(ctx, id)
					if err != nil {
						continue
					}
					if s == nil {
						if err := st.Views.Delete(ctx, id); err == nil {
							dropped++
						}
					}
				}
				if dropped > 0 {
					log.Debug("views sweep: dropped orphan records", "count", dropped)
				}
			}
		}
	}()
}

// buildOIDCRegistry maps the env config to the core oidc config, warns on
// dangerous postures, and builds the registry (discovery runs here, fail-fast).
func buildOIDCRegistry(cfg *env.Config, log *slog.Logger) (*paoidc.Registry, error) {
	cfgs := make([]paoidc.Config, 0, len(cfg.Auth.OIDC))
	for _, p := range cfg.Auth.OIDC {
		requireVerified := true
		if p.RequireEmailVerified != nil {
			requireVerified = *p.RequireEmailVerified
		}
		cfgs = append(cfgs, paoidc.Config{
			ID:                   p.ID,
			Label:                p.Label,
			Issuer:               p.Issuer,
			ClientID:             p.ClientID,
			ClientSecret:         p.ClientSecret,
			RedirectURL:          p.RedirectURL,
			Scopes:               p.Scopes,
			RequireEmailVerified: requireVerified,
			AllowedDomains:       p.AllowedDomains,
			AllowedEmails:        p.AllowedEmails,
			GroupsClaim:          p.GroupsClaim,
			AdminEmails:          p.AdminEmails,
			AdminGroups:          p.AdminGroups,
			UserGroups:           p.UserGroups,
			DefaultRole:          p.DefaultRole,
		})

		noLists := len(p.AllowedDomains) == 0 && len(p.AllowedEmails) == 0 &&
			len(p.AdminEmails) == 0 && len(p.AdminGroups) == 0 && len(p.UserGroups) == 0
		if noLists {
			log.Warn("auth: OIDC provider has NO admission lists (allowed_domains/allowed_emails/"+
				"admin_emails/admin_groups/user_groups all empty): every account the identity "+
				"provider authenticates will be admitted", "provider", p.ID)
		}
		noRoleGrants := len(p.AdminEmails) == 0 && len(p.AdminGroups) == 0 && len(p.UserGroups) == 0
		switch p.DefaultRole {
		case "", "none":
			if noRoleGrants {
				log.Warn("auth: OIDC provider default_role is \"none\" (deny) and no admin/user "+
					"emails/groups are set: every login will be denied (seed an admin via "+
					"`secret-share user create`, or grant a role)", "provider", p.ID)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reg, err := paoidc.NewRegistry(ctx, cfgs)
	if err != nil {
		return nil, err
	}
	for _, p := range cfg.Auth.OIDC {
		log.Info("auth: oidc provider ready", "id", p.ID, "issuer", p.Issuer)
	}
	return reg, nil
}

// absPath resolves p to an absolute path, returning "" for an empty input.
func absPath(p string) string {
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}
