package server

import (
	"encoding/json"
	"fmt"

	"github.com/gofiber/fiber/v2"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
)

// Multi-view secrets live entirely at the edge (like per-secret visibility):
// the secrets domain still knows only exactly-once burn. A secret created with
// views=N gets a side record holding the budget plus a ciphertext copy;
// non-final reveals are served from that record and never touch the secret, and
// the final view falls through to the normal reveal/burn path, so "reveal is
// the single burn path" stays true.

// maxViews returns the operator ceiling (>=1; 1 disables multi-view).
func maxViews(rt *env.Runtime) int {
	if v := rt.Config.Secrets.MaxViews; v > 1 {
		return v
	}
	return 1
}

// captureViews runs around the create handler. It rejects an out-of-range
// views request up front, and after a successful create records the budget
// BEFORE the response is flushed (so a multi-view secret is never briefly
// one-time). views absent, 0 or 1 means a plain one-time secret.
func captureViews(rt *env.Runtime, st *store.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Views      int    `json:"views"`
			Ciphertext string `json:"ciphertext"`
		}
		// Body-shape errors are left for the create handler to report.
		if err := json.Unmarshal(c.Body(), &req); err == nil {
			if req.Views < 0 || req.Views > maxViews(rt) {
				return response.Error(c, fiber.StatusBadRequest,
					fmt.Sprintf("views must be between 1 and %d", maxViews(rt)))
			}
		}
		if err := c.Next(); err != nil {
			return err
		}
		if req.Views <= 1 {
			return nil
		}
		if code := c.Response().StatusCode(); code < 200 || code >= 300 {
			return nil
		}
		var resp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(c.Response().Body(), &resp); err != nil || resp.ID == "" {
			return nil
		}
		if err := st.Views.Put(c.UserContext(), resp.ID, req.Views, req.Ciphertext); err != nil {
			// Losing the record degrades to one-time, never to extra views.
			rt.Log.Error("failed to record secret view budget", "id", resp.ID, "err", err)
		}
		return nil
	}
}

// multiViewReveal runs before the reveal handler. For a multi-view secret it
// atomically consumes one view and serves the stored ciphertext while views
// remain - never touching the secret record. The final view (and every plain
// one-time secret) falls through to the real reveal, which burns.
func multiViewReveal(st *store.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ct, remaining, found, err := st.Views.Consume(c.UserContext(), c.Params("id"))
		if err != nil {
			return response.Internal(c, err)
		}
		if found && remaining > 0 {
			return c.JSON(fiber.Map{
				"ciphertext":      ct,
				"views_remaining": remaining,
			})
		}
		return c.Next()
	}
}

// annotateViewsMeta runs after the meta handler and adds views_remaining to the
// response for multi-view secrets, so the reveal page can tell the recipient
// the secret survives this view. Best-effort: any decode hiccup leaves the
// original response untouched.
func annotateViewsMeta(st *store.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := c.Next(); err != nil {
			return err
		}
		if c.Response().StatusCode() != fiber.StatusOK {
			return nil
		}
		remaining, found, err := st.Views.Remaining(c.UserContext(), c.Params("id"))
		if err != nil || !found {
			return nil
		}
		var body map[string]any
		if err := json.Unmarshal(c.Response().Body(), &body); err != nil || body == nil {
			return nil
		}
		body["views_remaining"] = remaining
		out, err := json.Marshal(body)
		if err != nil {
			return nil
		}
		c.Response().SetBody(out)
		return nil
	}
}
