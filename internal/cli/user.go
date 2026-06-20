package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/database/boltkv"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

// newUserCmd is the `user` command group: out-of-band management of the console
// users used in private mode. Its main job is `user create`, which seeds the
// first admin so the server can start with auth enabled (see ensureBootstrapAdmin).
func newUserCmd() *cobra.Command {
	user := &cobra.Command{
		Use:   "user",
		Short: "Manage console users (private-mode users)",
	}
	user.PersistentFlags().StringP("config", "c", "", "path to YAML config (default: ./secret-share.yaml)")

	create := &cobra.Command{
		Use:   "create [email]",
		Short: "Create (or update) a user user",
		Long: "Create a user so they can sign in when auth is enabled. Defaults to an admin\n" +
			"(so the server is reachable on first boot); pass --role user for a regular user.\n" +
			"Local users get a password (prompted); pass --oidc for an SSO-only account (email only).",
		Args: cobra.MaximumNArgs(1),
		RunE: runUserCreate,
	}
	create.Flags().StringP("email", "e", "", "user email (positional arg or prompted if omitted)")
	create.Flags().String("password", "", "password (prompted if omitted; local accounts only)")
	create.Flags().String("role", "admin", "role: admin or user")
	create.Flags().Bool("oidc", false, "create an OIDC-only account (no local password)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List user users",
		RunE:  runUserList,
	}

	del := &cobra.Command{
		Use:   "delete <email>",
		Short: "Delete a user user",
		Args:  cobra.ExactArgs(1),
		RunE:  runUserDelete,
	}

	setRole := &cobra.Command{
		Use:   "set-role <email> <admin|user>",
		Short: "Change a user's role",
		Args:  cobra.ExactArgs(2),
		RunE:  runUserSetRole,
	}

	resetPw := &cobra.Command{
		Use:   "reset-password <email>",
		Short: "Set or replace a user's local password",
		Args:  cobra.ExactArgs(1),
		RunE:  runUserResetPassword,
	}
	resetPw.Flags().String("password", "", "new password (prompted if omitted)")

	user.AddCommand(create, list, del, setRole, resetPw)
	return user
}

// openUserStore loads the config and opens the embedded boltkv store in a minimal
// Runtime, so the user store works without booting the full server.
func openUserStore(cmd *cobra.Command) (*env.Config, *store.Store, func() error, error) {
	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := env.Load(configPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load config: %w", err)
	}
	kv, err := boltkv.Open(cfg.Database.Path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open store %q: %w", cfg.Database.Path, err)
	}
	rt := &env.Runtime{Config: cfg}
	st := &store.Store{}
	boltkv.BindProvider(rt, st, kv)
	return cfg, st, kv.Close, nil
}

func runUserCreate(cmd *cobra.Command, args []string) error {
	_, st, closeStore, err := openUserStore(cmd)
	if err != nil {
		return err
	}
	defer closeStore()
	ctx := context.Background()
	out := cmd.OutOrStdout()

	email, _ := cmd.Flags().GetString("email")
	if len(args) == 1 {
		email = args[0]
	}
	email = user.NormalizeEmail(email)
	if email == "" {
		email, err = promptLine(cmd, "User email: ")
		if err != nil {
			return err
		}
		email = user.NormalizeEmail(email)
	}
	if email == "" || !strings.Contains(email, "@") {
		return fmt.Errorf("a valid email is required")
	}

	role, ok := user.ParseRole(mustFlag(cmd, "role"))
	if !ok {
		return fmt.Errorf("invalid --role %q: want admin or user", mustFlag(cmd, "role"))
	}

	existing, err := st.Users.Get(ctx, email)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	p := existing
	if p == nil {
		p = &user.User{Email: email, Enabled: true}
	}
	p.Role = role
	p.Enabled = true
	p.Pinned = role == user.RoleAdmin // pin admins against OIDC downgrade/lockout

	oidcOnly, _ := cmd.Flags().GetBool("oidc")
	if oidcOnly {
		if p.Source == "" {
			p.Source = user.SourceOIDC
		}
		fmt.Fprintf(out, "created an OIDC-only account for %s (sign in via SSO; no password set).\n", email)
	} else {
		password := mustFlag(cmd, "password")
		if password == "" {
			password, err = promptPasswordTwice(cmd)
			if err != nil {
				return err
			}
		}
		if n := len(password); n < 8 || n > 72 {
			// 72 bytes is bcrypt's hard limit (SetPassword errors above it).
			return fmt.Errorf("password must be 8-72 characters")
		}
		if err := p.SetPassword(password); err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		p.Source = user.SourceLocal
	}

	if err := st.Users.Upsert(ctx, p); err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	verb := "created"
	if existing != nil {
		verb = "updated"
	}
	fmt.Fprintf(out, "user %s: %s (role=%s)\n", verb, email, p.Role)
	return nil
}

func runUserList(cmd *cobra.Command, _ []string) error {
	_, st, closeStore, err := openUserStore(cmd)
	if err != nil {
		return err
	}
	defer closeStore()

	ps, err := st.Users.List(context.Background())
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	out := cmd.OutOrStdout()
	if len(ps) == 0 {
		fmt.Fprintln(out, "no users yet - run `secret-share user create`")
		return nil
	}
	fmt.Fprintf(out, "%-32s %-7s %-7s %-8s %-7s %s\n", "EMAIL", "ROLE", "SOURCE", "ENABLED", "2FA", "PINNED")
	for _, p := range ps {
		fmt.Fprintf(out, "%-32s %-7s %-7s %-8t %-7t %t\n", p.Email, p.Role, p.Source, p.Enabled, p.TOTPEnabled, p.Pinned)
	}
	return nil
}

func runUserDelete(cmd *cobra.Command, args []string) error {
	_, st, closeStore, err := openUserStore(cmd)
	if err != nil {
		return err
	}
	defer closeStore()
	ctx := context.Background()
	email := user.NormalizeEmail(args[0])

	p, err := st.Users.Get(ctx, email)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if p == nil {
		return fmt.Errorf("no such user: %s", email)
	}
	if p.Role == user.RoleAdmin {
		if err := guardLastAdmin(ctx, st); err != nil {
			return err
		}
	}
	if err := st.Users.Delete(ctx, email); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "user deleted: %s\n", email)
	return nil
}

func runUserSetRole(cmd *cobra.Command, args []string) error {
	_, st, closeStore, err := openUserStore(cmd)
	if err != nil {
		return err
	}
	defer closeStore()
	ctx := context.Background()
	email := user.NormalizeEmail(args[0])

	role, ok := user.ParseRole(args[1])
	if !ok {
		return fmt.Errorf("invalid role %q: want admin or user", args[1])
	}
	p, err := st.Users.Get(ctx, email)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if p == nil {
		return fmt.Errorf("no such user: %s", email)
	}
	if p.Role == user.RoleAdmin && role != user.RoleAdmin {
		if err := guardLastAdmin(ctx, st); err != nil {
			return err
		}
	}
	p.Role = role
	p.Pinned = role == user.RoleAdmin
	if err := st.Users.Upsert(ctx, p); err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "user %s role set to %s\n", email, role)
	return nil
}

func runUserResetPassword(cmd *cobra.Command, args []string) error {
	_, st, closeStore, err := openUserStore(cmd)
	if err != nil {
		return err
	}
	defer closeStore()
	ctx := context.Background()
	email := user.NormalizeEmail(args[0])

	p, err := st.Users.Get(ctx, email)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if p == nil {
		return fmt.Errorf("no such user: %s", email)
	}
	password := mustFlag(cmd, "password")
	if password == "" {
		password, err = promptPasswordTwice(cmd)
		if err != nil {
			return err
		}
	}
	if n := len(password); n < 8 || n > 72 {
		return fmt.Errorf("password must be 8-72 characters")
	}
	if err := p.SetPassword(password); err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	p.Source = user.SourceLocal
	if err := st.Users.Upsert(ctx, p); err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "password updated for %s\n", email)
	return nil
}

// guardLastAdmin returns an error when there is only one admin left, so the
// caller refuses to delete or demote it (which would lock everyone out).
func guardLastAdmin(ctx context.Context, st *store.Store) error {
	n, err := st.Users.CountByRole(ctx, user.RoleAdmin)
	if err != nil {
		return fmt.Errorf("count admins: %w", err)
	}
	if n <= 1 {
		return fmt.Errorf("refusing to remove the last admin; create another admin first")
	}
	return nil
}

func mustFlag(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

// promptLine writes prompt to stderr and reads a trimmed line from stdin.
func promptLine(cmd *cobra.Command, prompt string) (string, error) {
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	r := bufio.NewReader(cmd.InOrStdin())
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// promptPasswordTwice reads a password without echo (when stdin is a terminal)
// and a confirmation, requiring the two to match.
func promptPasswordTwice(cmd *cobra.Command) (string, error) {
	stderr := cmd.ErrOrStderr()
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Non-interactive (piped): read a single line as the password.
		return promptLine(cmd, "Password: ")
	}
	fmt.Fprint(stderr, "Password: ")
	pw1, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Fprint(stderr, "Confirm password: ")
	pw2, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(pw1) != string(pw2) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(pw1), nil
}
