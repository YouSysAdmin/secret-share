package files

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/models/file"
)

// Handler serves the encrypted-file endpoints. The request body is the raw
// opaque blob (application/octet-stream); creation options ride headers
// because the body is not JSON:
//
//	X-Share-TTL:     lifetime as a Go duration (default secrets.default_ttl)
//	X-Share-Private: "true" marks the file private (recorded by the edge
//	                 middleware, not here - listed for API completeness)
type Handler struct {
	Runtime *env.Runtime
	Store   *store.Store
}

// TTLHeader / PrivateHeader are the creation-option header names (shared with
// the edge middleware).
const (
	TTLHeader     = "X-Share-TTL"
	PrivateHeader = "X-Share-Private"
)

// Create stores a new encrypted file blob and returns its id.
func (h *Handler) Create(c *fiber.Ctx) error {
	cfg := h.Runtime.Config
	if !cfg.Files.Enabled {
		return response.NotFound(c, "")
	}

	body := c.Body()
	if len(body) == 0 {
		return response.Error(c, fiber.StatusBadRequest, "empty body")
	}
	if len(body) > cfg.Files.MaxSizeBytes {
		return response.Error(c, fiber.StatusRequestEntityTooLarge,
			fmt.Sprintf("file exceeds the %d byte limit", cfg.Files.MaxSizeBytes))
	}

	ttl := cfg.DefaultTTLDuration()
	if raw := strings.TrimSpace(c.Get(TTLHeader)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return response.Error(c, fiber.StatusBadRequest, "invalid ttl")
		}
		if d > cfg.MaxTTLDuration() {
			return response.Error(c, fiber.StatusBadRequest,
				fmt.Sprintf("ttl exceeds the maximum of %s", cfg.MaxTTLDuration()))
		}
		ttl = d
	}

	id, err := file.NewID()
	if err != nil {
		return response.Internal(c, err)
	}
	now := time.Now()
	f := &file.File{
		ID: id,
		// Copy: the fasthttp body buffer is reused after the handler returns.
		Ciphertext: append([]byte(nil), body...),
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		Size:       len(body),
	}
	if err := h.Store.Files.Create(c.UserContext(), f); err != nil {
		return response.Internal(c, err)
	}
	return response.OK(c, fiber.Map{"id": id})
}

// Meta reports whether the file still exists (and its size) without burning
// it. Like the secrets meta, a missing file is a 200 + exists:false so the SPA
// can render the "gone" state from one shape.
func (h *Handler) Meta(c *fiber.Ctx) error {
	f, err := h.Store.Files.GetMeta(c.UserContext(), c.Params("id"))
	if err != nil {
		return response.Internal(c, err)
	}
	if f == nil {
		return response.OK(c, fiber.Map{"exists": false})
	}
	return response.OK(c, fiber.Map{"exists": true, "size": f.Size})
}

// Reveal atomically burns the file and streams its ciphertext. POST-only for
// the same reason as the secrets reveal: GET/HEAD prefetchers must never
// consume a link.
func (h *Handler) Reveal(c *fiber.Ctx) error {
	f, err := h.Store.Files.GetAndBurn(c.UserContext(), c.Params("id"))
	if err != nil {
		return response.Internal(c, err)
	}
	if f == nil {
		return response.NotFound(c, "")
	}
	c.Set(fiber.HeaderContentType, "application/octet-stream")
	return c.Send(f.Ciphertext)
}
