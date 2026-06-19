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
)

// Store is the aggregate handle passed to handlers alongside the Runtime.
type Store struct {
	Secrets SecretStore
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
