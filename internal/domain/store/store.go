// Package store declares the aggregate persistence handle and the per-domain
// interface the bbolt backend implements (boltkv's BindProvider fills the
// slot). Defining the interface here - referencing only the model package -
// keeps the import graph acyclic: store <- domain/<thing> (impls) <- handlers.
// The interface takes a context.Context (carried through for cancellation and
// to keep this layer decoupled from the HTTP request type).
package store

import (
	"context"
	"time"

	"github.com/YouSysAdmin/secret-share/internal/models/secret"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

// Store is the aggregate handle passed to handlers alongside the Runtime.
type Store struct {
	Secrets SecretStore
	// Users persists console identities for private mode. Bound always (even
	// when auth is disabled), so the CLI user commands work regardless.
	Users UserStore
	// Visibility records which secrets are private (require a session to reveal).
	// Kept apart from the secret record so the auth layer can enforce per-secret
	// visibility without reaching into the secrets domain.
	Visibility SecretVisibilityStore
}

// SecretVisibilityStore records which secret ids are private (require a session
// to preview/reveal). Presence of an id means private; absence means public.
type SecretVisibilityStore interface {
	// SetPrivate marks a secret id private.
	SetPrivate(ctx context.Context, id string) error
	// IsPrivate reports whether the secret id is marked private.
	IsPrivate(ctx context.Context, id string) (bool, error)
	// Delete drops a secret id's visibility record (no-op if absent).
	Delete(ctx context.Context, id string) error
	// List returns every recorded (private) secret id, for orphan cleanup.
	List(ctx context.Context) ([]string, error)
}

// UserStore persists console users (admins + users), keyed by their
// lowercased email. Used only when auth (private mode) is enabled, plus the CLI.
type UserStore interface {
	// Get returns the user for email, or (nil, nil) when none exists.
	Get(ctx context.Context, email string) (*user.User, error)
	// List returns every user (email-ascending).
	List(ctx context.Context) ([]*user.User, error)
	// Upsert creates or replaces a user, preserving CreatedAt across updates.
	Upsert(ctx context.Context, p *user.User) error
	// Delete removes the user for email (no-op if absent).
	Delete(ctx context.Context, email string) error
	// CountByRole counts users holding the given role (used for the
	// last-admin lockout guard).
	CountByRole(ctx context.Context, role user.Role) (int, error)
}

// SecretStore persists secrets, keyed by their random id.
type SecretStore interface {
	// Create stores a new secret.
	Create(ctx context.Context, s *secret.Secret) error
	// GetMeta returns the secret's metadata, or (nil, nil) when absent. It must
	// NOT burn the secret and the caller must not treat the returned Ciphertext as
	// consumed.
	GetMeta(ctx context.Context, id string) (*secret.Secret, error)
	// GetAndBurn atomically returns the secret and deletes it in one transaction,
	// so a secret is yielded exactly once even under concurrent reads. Returns
	// (nil, nil) when already gone. This is the exactly-once primitive.
	GetAndBurn(ctx context.Context, id string) (*secret.Secret, error)
	// Delete removes the secret for id (no-op if absent).
	Delete(ctx context.Context, id string) error
	// DeleteExpired purges secrets whose ExpiresAt is at or before now and returns
	// the count removed. Driven by the background sweeper.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}
