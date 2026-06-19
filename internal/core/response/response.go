// Package response is the tiny shared helper layer between domain handlers and
// Fiber: JSON success/error writers with a consistent {"error": msg} envelope.
package response

import (
	"log/slog"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// JSON writes v as a JSON body with the given status code.
func JSON(c *fiber.Ctx, code int, v any) error {
	return c.Status(code).JSON(v)
}

// OK writes v as a JSON body with a 200 status.
func OK(c *fiber.Ctx, v any) error {
	return c.Status(http.StatusOK).JSON(v)
}

// Error writes a {"error": msg} body with the given status.
func Error(c *fiber.Ctx, code int, msg string) error {
	return c.Status(code).JSON(fiber.Map{"error": msg})
}

func BadRequest(c *fiber.Ctx, err error) error {
	msg := "bad request"
	if err != nil {
		msg = err.Error()
	}
	return Error(c, http.StatusBadRequest, msg)
}

func Forbidden(c *fiber.Ctx, msg string) error {
	if msg == "" {
		msg = "forbidden"
	}
	return Error(c, http.StatusForbidden, msg)
}

func NotFound(c *fiber.Ctx, msg string) error {
	if msg == "" {
		msg = "not found"
	}
	return Error(c, http.StatusNotFound, msg)
}

func TooManyRequests(c *fiber.Ctx, msg string) error {
	if msg == "" {
		msg = "too many requests"
	}
	return Error(c, http.StatusTooManyRequests, msg)
}

// Internal logs the underlying error server-side and returns a generic 500.
// It never leaks error detail to the client - important for an app that handles
// secrets and exposes some endpoints unauthenticated.
func Internal(c *fiber.Ctx, err error) error {
	if err != nil {
		slog.Error("request failed", "path", c.Path(), "method", c.Method(), "err", err)
	}
	return Error(c, http.StatusInternalServerError, "internal error")
}
