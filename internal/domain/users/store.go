// Package users is the bbolt-backed store for console users (admins +
// users) plus their admin-only management endpoints. The User model + Role
// constants live in internal/models/user (imported as usermodel) so
// handlers can build users without importing this package.
//
// Mirrors the secret store idiom: NewStore(db, bucket) holds the bbolt handle +
// bucket name directly and methods take a context.Context (carried for
// cancellation), keeping this layer decoupled from the HTTP request type.
package users

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"

	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	usermodel "github.com/YouSysAdmin/secret-share/internal/models/user"
)

// Store persists users in one bbolt bucket, keyed by lowercased email. It
// implements store.UserStore.
type Store struct {
	db     *bbolt.DB
	bucket []byte
}

// compile-time check.
var _ store.UserStore = (*Store)(nil)

// NewStore returns a user store backed by db, persisting into bucket.
func NewStore(db *bbolt.DB, bucket string) *Store {
	return &Store{db: db, bucket: []byte(bucket)}
}

func key(email string) []byte { return []byte(usermodel.NormalizeEmail(email)) }

// Get returns the user for email, or (nil, nil) when none exists.
func (s *Store) Get(_ context.Context, email string) (*usermodel.User, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	var out *usermodel.User
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		raw := b.Get(key(email))
		if raw == nil {
			return nil
		}
		var p usermodel.User
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		out = &p
		return nil
	})
	return out, err
}

// List returns every user, sorted by the bbolt key order (email asc).
func (s *Store) List(_ context.Context) ([]*usermodel.User, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	var out []*usermodel.User
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var p usermodel.User
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			out = append(out, &p)
			return nil
		})
	})
	return out, err
}

// Upsert creates or replaces the user keyed by its (normalized) email,
// stamping CreatedAt on first write and UpdatedAt on every write.
func (s *Store) Upsert(_ context.Context, p *usermodel.User) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not open")
	}
	if p == nil || p.Email == "" {
		return fmt.Errorf("user email required")
	}
	p.Email = usermodel.NormalizeEmail(p.Email)
	now := time.Now().UTC()
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(s.bucket)
		if err != nil {
			return err
		}
		// Preserve the original CreatedAt across updates.
		if existing := b.Get(key(p.Email)); existing != nil {
			var prev usermodel.User
			if err := json.Unmarshal(existing, &prev); err == nil && !prev.CreatedAt.IsZero() {
				p.CreatedAt = prev.CreatedAt
			}
		}
		if p.CreatedAt.IsZero() {
			p.CreatedAt = now
		}
		p.UpdatedAt = now
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return b.Put(key(p.Email), raw)
	})
}

// Delete removes the user for email. Deleting an absent key is a no-op.
func (s *Store) Delete(_ context.Context, email string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not open")
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		return b.Delete(key(email))
	})
}

// CountByRole counts users holding the given role.
func (s *Store) CountByRole(_ context.Context, role usermodel.Role) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	n := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var p usermodel.User
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			if p.Role == role {
				n++
			}
			return nil
		})
	})
	return n, err
}
