package oidc

import (
	"fmt"
	"strings"

	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

// Admit decides whether a verified user may sign in at all (RoleFor then assigns
// their role). Admitted if they match ANY rule:
//
//   - allowed_emails / admin_emails  (an admin email also makes them admin via
//     RoleFor, so listing an admin needs nothing else)
//   - allowed_domains                (their email's domain)
//   - admin_groups OR user_groups    (the role-mapped groups double as the group
//     allowlist - there is no separate allowed_groups)
//
// When none of those are configured, the IdP is the only gate and every
// authenticated user is admitted (serve.go warns about this). Returns the user's
// groups for the caller to pass to RoleFor + the cookie.
func (p *Provider) Admit(c *Claims) (groups []string, err error) {
	cfg := p.cfg

	if cfg.RequireEmailVerified && !c.EmailVerified {
		return nil, fmt.Errorf("email %q not verified by issuer (if the IdP does not emit the email_verified claim, set require_email_verified: false)", c.Email)
	}

	email := strings.TrimSpace(strings.ToLower(c.Email))
	gs := extractGroups(c, cfg.GroupsClaim)

	// By email: explicit allowlist or any admin email.
	if matchEmail(email, cfg.AllowedEmails) || matchEmail(email, cfg.AdminEmails) {
		return gs, nil
	}

	// By domain.
	if len(cfg.AllowedDomains) > 0 {
		if at := strings.LastIndex(email, "@"); at >= 0 {
			host := email[at+1:]
			for _, d := range cfg.AllowedDomains {
				if host == d {
					return gs, nil
				}
			}
		}
	}

	// By group: the union of the role-mapped groups (admin + user).
	if cfg.GroupsClaim != "" && (len(cfg.AdminGroups) > 0 || len(cfg.UserGroups) > 0) {
		if anyGroupMatch(gs, cfg.AdminGroups) || anyGroupMatch(gs, cfg.UserGroups) {
			return gs, nil
		}
	}

	// No admission lists configured at all -> open to any authenticated user.
	if len(cfg.AllowedEmails) == 0 && len(cfg.AdminEmails) == 0 &&
		len(cfg.AllowedDomains) == 0 && len(cfg.AdminGroups) == 0 && len(cfg.UserGroups) == 0 {
		return gs, nil
	}

	return nil, fmt.Errorf("user %q (%s) not in any allowlist", c.Subject, c.Email)
}

// matchEmail reports whether email (already lowercased) is in want (lowercased
// by config validation).
func matchEmail(email string, want []string) bool {
	for _, e := range want {
		if email == e {
			return true
		}
	}
	return false
}

// RoleFor maps an admitted user to a role. Precedence: admin_emails ->
// admin_groups -> user_groups -> default_role, so a user in both an admin and a
// user group is an admin. groups are the values Admit extracted from the ID
// token. Config lists are lowercased by validation; incoming groups are
// lowercased here for comparison.
//
// ok reports whether any rule granted a role at all. When it is false the user
// matched no admin/user rule and default_role is "none" (or empty): there is no
// implicit role, so the caller must DENY the login (fail closed) even though
// Admit may have let them in by email/domain. pinned reports an admin_emails
// match, which pins the user to admin (exempt from group-based downgrade).
func (p *Provider) RoleFor(c *Claims, groups []string) (role user.Role, pinned, ok bool) {
	cfg := p.cfg
	email := strings.TrimSpace(strings.ToLower(c.Email))

	for _, e := range cfg.AdminEmails {
		if email == e {
			return user.RoleAdmin, true, true
		}
	}
	if len(cfg.AdminGroups) > 0 && anyGroupMatch(groups, cfg.AdminGroups) {
		return user.RoleAdmin, false, true
	}
	if len(cfg.UserGroups) > 0 && anyGroupMatch(groups, cfg.UserGroups) {
		return user.RoleUser, false, true
	}
	// Fallback. "" and "none" both mean "no implicit role" -> deny.
	switch user.Role(strings.ToLower(strings.TrimSpace(cfg.DefaultRole))) {
	case user.RoleAdmin:
		return user.RoleAdmin, false, true
	case user.RoleUser:
		return user.RoleUser, false, true
	default:
		return "", false, false
	}
}

// anyGroupMatch reports whether any of the user's groups (any case) appears in
// want (already lowercased).
func anyGroupMatch(groups, want []string) bool {
	for _, g := range groups {
		gl := strings.ToLower(g)
		for _, w := range want {
			if gl == w {
				return true
			}
		}
	}
	return false
}

func extractGroups(c *Claims, claim string) []string {
	if claim == "" || c.Raw == nil {
		return nil
	}
	raw, ok := c.Raw[claim]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, g := range v {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		return []string{v}
	}
	return nil
}
