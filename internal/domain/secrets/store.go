// Package secrets is the bbolt-backed store for secrets plus the create/meta/reveal
// endpoints. The Secret model lives in internal/core/secret.
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"

	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/models/secret"
)

// compile-time check.
var _ store.SecretStore = (*Store)(nil)

// Store persists secrets in one bbolt bucket, keyed by id.
type Store struct {
	db     *bbolt.DB
	bucket []byte
}

// NewStore returns a bbolt-backed SecretStore over the given handle + bucket.
func NewStore(db *bbolt.DB, bucket string) *Store {
	return &Store{db: db, bucket: []byte(bucket)}
}

// Create stores a new secret, failing on an id collision
// (so a generated id is never silently overwritten).
func (s *Store) Create(_ context.Context, sec *secret.Secret) error {
	if s.db == nil {
		return fmt.Errorf("store not open")
	}
	if sec == nil || sec.ID == "" {
		return fmt.Errorf("secret id required")
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(s.bucket)
		if err != nil {
			return err
		}
		if b.Get([]byte(sec.ID)) != nil {
			return fmt.Errorf("secret id collision")
		}
		raw, err := json.Marshal(sec)
		if err != nil {
			return err
		}
		return b.Put([]byte(sec.ID), raw)
	})
}

// GetMeta returns the secret for id without burning it, or (nil, nil) when absent.
func (s *Store) GetMeta(_ context.Context, id string) (*secret.Secret, error) {
	if s.db == nil {
		return nil, nil
	}
	var out *secret.Secret
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return nil
		}
		var sec secret.Secret
		if err := json.Unmarshal(raw, &sec); err != nil {
			return err
		}
		out = &sec
		return nil
	})
	return out, err
}

// GetAndBurn atomically reads and deletes the secret in a single write
// transaction. bbolt serializes writers, so two concurrent reveals resolve to
// exactly one non-nil result; the loser sees (nil, nil).
func (s *Store) GetAndBurn(_ context.Context, id string) (*secret.Secret, error) {
	if s.db == nil {
		return nil, nil
	}
	var out *secret.Secret
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return nil
		}
		var sec secret.Secret
		if err := json.Unmarshal(raw, &sec); err != nil {
			return err
		}
		if err := b.Delete([]byte(id)); err != nil {
			return err
		}
		out = &sec
		return nil
	})
	return out, err
}

// Delete removes the secret for id (no-op if absent).
func (s *Store) Delete(_ context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("store not open")
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	})
}

// DeleteExpired purges every secret whose ExpiresAt is at or before now and
// returns the count removed.
// Uses a cursor (Cursor.Delete is safe during iteration) inside one write transaction.
func (s *Store) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	if s.db == nil {
		return 0, nil
	}
	count := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var sec secret.Secret
			if err := json.Unmarshal(v, &sec); err != nil {
				continue // skip undecodable rows rather than abort the sweep
			}
			if sec.IsExpired(now) {
				if err := c.Delete(); err != nil {
					return err
				}
				count++
			}
		}
		return nil
	})
	return count, err
}
