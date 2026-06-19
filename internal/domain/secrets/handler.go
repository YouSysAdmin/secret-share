package secrets

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/models/secret"
)

type Handler struct {
	Runtime *env.Runtime
	Store   *store.Store
}

type createRequest struct {
	TTL        string `json:"ttl"`        // optional Go duration; capped at secrets.max_ttl
	Ciphertext string `json:"ciphertext"` // browser AES-GCM blob (base64)
}

// Create stores a new zero-knowledge secret: the server keeps the browser's
// opaque ciphertext, which it cannot decrypt.
// Open by design - no account needed.
func (h *Handler) Create(c *fiber.Ctx) error {
	var body createRequest
	if err := c.BodyParser(&body); err != nil {
		return response.BadRequest(c, err)
	}
	ct := body.Ciphertext
	if strings.TrimSpace(ct) == "" {
		return response.Error(c, http.StatusBadRequest, "ciphertext is required")
	}
	// The server can't read the plaintext; cap the opaque blob generously
	// (base64 of plaintext + AES-GCM overhead).
	if len(ct) > h.Runtime.Config.Secrets.MaxSizeBytes*2+1024 {
		return response.Error(c, http.StatusRequestEntityTooLarge, "secret too large")
	}

	ttl, err := h.resolveTTL(body.TTL)
	if err != nil {
		return response.BadRequest(c, err)
	}

	id, err := secret.NewID()
	if err != nil {
		return response.Internal(c, err)
	}
	now := time.Now().UTC()
	sec := &secret.Secret{
		ID:         id,
		Ciphertext: ct,
		Size:       len(ct),
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
	}
	if err := h.Store.Secrets.Create(c.UserContext(), sec); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("secret created", "id", id, "client_ip", c.IP())

	return response.JSON(c, http.StatusCreated, fiber.Map{
		"id":         id,
		"expires_at": sec.ExpiresAt,
	})
}

// Meta reports whether a secret exists, WITHOUT burning it. Powers the
// click-to-reveal gate. Missing, burned and expired all read identically as
// {exists:false} so the endpoint is no oracle.
func (h *Handler) Meta(c *fiber.Ctx) error {
	id := c.Params("id")
	sec, err := h.Store.Secrets.GetMeta(c.UserContext(), id)
	if err != nil {
		return response.Internal(c, err)
	}
	if sec == nil {
		return response.OK(c, fiber.Map{"exists": false})
	}
	if sec.IsExpired(time.Now()) {
		_ = h.Store.Secrets.Delete(c.UserContext(), id) // lazily reap
		return response.OK(c, fiber.Map{"exists": false})
	}
	return response.OK(c, fiber.Map{"exists": true, "size": sec.Size})
}

// Reveal is the single burn path (POST so link prefetchers/unfurlers, which
// issue GET/HEAD, can't trigger it). It returns the opaque ciphertext for
// in-browser decryption and deletes the secret exactly once.
func (h *Handler) Reveal(c *fiber.Ctx) error {
	id := c.Params("id")

	// Peek to drop an expired secret without consuming a live one's burn.
	if sec, err := h.Store.Secrets.GetMeta(c.UserContext(), id); err != nil {
		return response.Internal(c, err)
	} else if sec != nil && sec.IsExpired(time.Now()) {
		_ = h.Store.Secrets.Delete(c.UserContext(), id)
		return response.NotFound(c, "secret not found or already viewed")
	}

	// Atomic read+delete: exactly one concurrent reveal wins.
	burned, err := h.Store.Secrets.GetAndBurn(c.UserContext(), id)
	if err != nil {
		return response.Internal(c, err)
	}
	if burned == nil {
		return response.NotFound(c, "secret not found or already viewed")
	}
	h.Runtime.Log.Info("secret revealed", "id", id, "client_ip", c.IP())
	return response.OK(c, fiber.Map{"ciphertext": burned.Ciphertext})
}

// resolveTTL parses the requested TTL, defaulting to the configured default and
// rejecting anything over the configured maximum.
func (h *Handler) resolveTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return h.Runtime.Config.DefaultTTLDuration(), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("ttl %q invalid: want a Go duration like 1h", raw)
	}
	if d > h.Runtime.Config.MaxTTLDuration() {
		return 0, fmt.Errorf("ttl exceeds the maximum of %s", h.Runtime.Config.MaxTTLDuration())
	}
	return d, nil
}
