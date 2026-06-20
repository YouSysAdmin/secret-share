// Package secretvis is the bbolt-backed store for per-secret visibility: which
// secret ids are private (require a session to preview/reveal). It is kept
// separate from the secrets domain so the auth layer can enforce visibility
// without depending on (or modifying) the secret record itself.
//
// Presence of an id in the bucket means private; absence means public.
package secretvis

import (
	"context"

	"go.etcd.io/bbolt"

	"github.com/YouSysAdmin/secret-share/internal/domain/store"
)

// Store persists private-secret ids in one bbolt bucket. It implements
// store.SecretVisibilityStore.
type Store struct {
	db     *bbolt.DB
	bucket []byte
}

var _ store.SecretVisibilityStore = (*Store)(nil)

// marker is the (non-empty) value stored under each private id; only presence
// matters.
var marker = []byte{1}

// NewStore returns a visibility store backed by db, persisting into bucket.
func NewStore(db *bbolt.DB, bucket string) *Store {
	return &Store{db: db, bucket: []byte(bucket)}
}

// SetPrivate marks id private.
func (s *Store) SetPrivate(_ context.Context, id string) error {
	if s == nil || s.db == nil || id == "" {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(s.bucket)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), marker)
	})
}

// IsPrivate reports whether id is marked private.
func (s *Store) IsPrivate(_ context.Context, id string) (bool, error) {
	if s == nil || s.db == nil || id == "" {
		return false, nil
	}
	private := false
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		private = b.Get([]byte(id)) != nil
		return nil
	})
	return private, err
}

// Delete drops id's record (no-op if absent).
func (s *Store) Delete(_ context.Context, id string) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	})
}

// List returns every recorded (private) secret id.
func (s *Store) List(_ context.Context) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	var ids []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			ids = append(ids, string(k))
			return nil
		})
	})
	return ids, err
}
