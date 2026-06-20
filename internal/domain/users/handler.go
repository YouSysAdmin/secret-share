package users

import (
	"encoding/json"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	usermodel "github.com/YouSysAdmin/secret-share/internal/models/user"
)

// decodePasskeys counts entries in the user's opaque passkey blob without
// importing the passkey package (it's a JSON array of credential records).
func decodePasskeys(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return 0, err
	}
	return len(arr), nil
}

// Handler serves the admin-only user-management API; all routes sit behind
// requireRole(admin) in the route table.
type Handler struct {
	Runtime *env.Runtime
	Store   *store.Store
}

// view is the wire shape: a user with the password hash stripped.
type view struct {
	Email        string `json:"email"`
	Name         string `json:"name,omitempty"`
	Role         string `json:"role"`
	Source       string `json:"source"`
	Pinned       bool   `json:"pinned"`
	Enabled      bool   `json:"enabled"`
	HasPassword  bool   `json:"has_password"`
	TOTPEnabled  bool   `json:"totp_enabled"`
	PasskeyCount int    `json:"passkey_count"`
	Subject      string `json:"subject,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
	LastLoginAt  string `json:"last_login_at,omitempty"`
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"

func toView(p *usermodel.User) view {
	v := view{
		Email:       p.Email,
		Name:        p.Name,
		Role:        string(p.Role),
		Source:      p.Source,
		Pinned:      p.Pinned,
		Enabled:     p.Enabled,
		HasPassword: p.PasswordHash != "",
		TOTPEnabled: p.TOTPEnabled,
		Subject:     p.Subject,
	}
	if stored, err := decodePasskeys(p.Passkeys); err == nil {
		v.PasskeyCount = stored
	}
	if !p.CreatedAt.IsZero() {
		v.CreatedAt = p.CreatedAt.UTC().Format(rfc3339)
	}
	if !p.UpdatedAt.IsZero() {
		v.UpdatedAt = p.UpdatedAt.UTC().Format(rfc3339)
	}
	if p.LastLoginAt != nil && !p.LastLoginAt.IsZero() {
		v.LastLoginAt = p.LastLoginAt.UTC().Format(rfc3339)
	}
	return v
}

// List returns every user (password material excluded).
func (h *Handler) List(c *fiber.Ctx) error {
	ps, err := h.Store.Users.List(c.UserContext())
	if err != nil {
		return response.Internal(c, err)
	}
	out := make([]view, 0, len(ps))
	for _, p := range ps {
		out = append(out, toView(p))
	}
	return c.JSON(fiber.Map{"users": out})
}

type createReq struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Password string `json:"password"`
	Enabled  *bool  `json:"enabled"`
}

// Create adds a user. A password makes it a local (password-login) account;
// without one it's an OIDC account pre-provisioned by email (role applies once
// they sign in via SSO). Fails 409 if the email already exists.
func (h *Handler) Create(c *fiber.Ctx) error {
	var req createReq
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, err)
	}
	email := usermodel.NormalizeEmail(req.Email)
	if email == "" || !strings.Contains(email, "@") {
		return response.Error(c, fiber.StatusBadRequest, "a valid email is required")
	}
	role, ok := usermodel.ParseRole(req.Role)
	if req.Role != "" && !ok {
		return response.Error(c, fiber.StatusBadRequest, "role must be \"admin\" or \"user\"")
	}

	ctx := c.UserContext()
	if existing, err := h.Store.Users.Get(ctx, email); err != nil {
		return response.Internal(c, err)
	} else if existing != nil {
		return response.Error(c, fiber.StatusConflict, "a user with that email already exists")
	}

	p := &usermodel.User{
		Email:   email,
		Name:    strings.TrimSpace(req.Name),
		Role:    role,
		Enabled: req.Enabled == nil || *req.Enabled,
	}
	if req.Password != "" {
		if n := len(req.Password); n < 8 || n > 72 {
			// 72 bytes is bcrypt's hard limit (SetPassword errors above it).
			return response.Error(c, fiber.StatusBadRequest, "password must be 8-72 characters")
		}
		if err := p.SetPassword(req.Password); err != nil {
			return response.Internal(c, err)
		}
		p.Source = usermodel.SourceLocal
	} else {
		p.Source = usermodel.SourceOIDC
	}
	if err := h.Store.Users.Upsert(ctx, p); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("user created", "email", p.Email, "role", p.Role, "source", p.Source)
	return c.Status(fiber.StatusCreated).JSON(toView(p))
}

type updateReq struct {
	Name         *string `json:"name"`
	Role         *string `json:"role"`
	Enabled      *bool   `json:"enabled"`
	Password     *string `json:"password"`
	ClearTOTP    *bool   `json:"clear_totp"`     // admin: revoke the user's 2FA
	ClearPasskey *bool   `json:"clear_passkeys"` // admin: remove all the user's passkeys
}

// Update changes a user's name/role/enabled-state/password and can revoke
// their 2FA/passkeys. It refuses any change that would remove the last enabled
// admin (lockout guard).
func (h *Handler) Update(c *fiber.Ctx) error {
	email := usermodel.NormalizeEmail(c.Params("email"))
	ctx := c.UserContext()
	p, err := h.Store.Users.Get(ctx, email)
	if err != nil {
		return response.Internal(c, err)
	}
	if p == nil {
		return response.NotFound(c, "user not found")
	}

	var req updateReq
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, err)
	}

	next := *p // copy; apply requested changes
	if req.Name != nil {
		next.Name = strings.TrimSpace(*req.Name)
	}
	if req.Role != nil {
		role, ok := usermodel.ParseRole(*req.Role)
		if !ok {
			return response.Error(c, fiber.StatusBadRequest, "role must be \"admin\" or \"user\"")
		}
		next.Role = role
	}
	if req.Enabled != nil {
		next.Enabled = *req.Enabled
	}

	// Lockout guard: if this user is an enabled admin today and the change
	// would stop it being one, ensure another enabled admin remains.
	wasAdmin := p.Role == usermodel.RoleAdmin && p.Enabled
	stillAdmin := next.Role == usermodel.RoleAdmin && next.Enabled
	if wasAdmin && !stillAdmin {
		others, err := h.otherEnabledAdmins(c, p.Email)
		if err != nil {
			return response.Internal(c, err)
		}
		if others == 0 {
			return response.Error(c, fiber.StatusBadRequest, "cannot demote or disable the last enabled admin")
		}
	}

	if req.Password != nil {
		if *req.Password == "" {
			next.PasswordHash = "" // clear local password
		} else {
			if n := len(*req.Password); n < 8 || n > 72 {
				// 72 bytes is bcrypt's hard limit (SetPassword errors above it).
				return response.Error(c, fiber.StatusBadRequest, "password must be 8-72 characters")
			}
			if err := next.SetPassword(*req.Password); err != nil {
				return response.Internal(c, err)
			}
			if next.Source == "" {
				next.Source = usermodel.SourceLocal
			}
		}
	}
	if req.ClearTOTP != nil && *req.ClearTOTP {
		next.TOTPEnabled = false
		next.TOTPSecretEnc = ""
		next.RecoveryCodeHashes = nil
	}
	if req.ClearPasskey != nil && *req.ClearPasskey {
		next.Passkeys = nil
		next.WebAuthnHandle = nil
	}

	if err := h.Store.Users.Upsert(ctx, &next); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("user updated", "email", next.Email, "role", next.Role, "enabled", next.Enabled)
	return c.JSON(toView(&next))
}

// Delete removes a user, refusing to delete the last enabled admin.
func (h *Handler) Delete(c *fiber.Ctx) error {
	email := usermodel.NormalizeEmail(c.Params("email"))
	ctx := c.UserContext()
	p, err := h.Store.Users.Get(ctx, email)
	if err != nil {
		return response.Internal(c, err)
	}
	if p == nil {
		return response.NotFound(c, "user not found")
	}
	if p.Role == usermodel.RoleAdmin && p.Enabled {
		others, err := h.otherEnabledAdmins(c, p.Email)
		if err != nil {
			return response.Internal(c, err)
		}
		if others == 0 {
			return response.Error(c, fiber.StatusBadRequest, "cannot delete the last enabled admin")
		}
	}
	if err := h.Store.Users.Delete(ctx, email); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("user deleted", "email", email)
	return c.JSON(fiber.Map{"ok": true})
}

// otherEnabledAdmins counts enabled admins other than excludeEmail.
func (h *Handler) otherEnabledAdmins(c *fiber.Ctx, excludeEmail string) (int, error) {
	ps, err := h.Store.Users.List(c.UserContext())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range ps {
		if p.Email == excludeEmail {
			continue
		}
		if p.Role == usermodel.RoleAdmin && p.Enabled {
			n++
		}
	}
	return n, nil
}
