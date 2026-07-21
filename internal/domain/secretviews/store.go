// Package secretviews is the bbolt-backed store for multi-view budgets:
// secrets created with views > 1. It is kept separate from the secrets domain
// (same layering as secretvis) so the edge can serve non-final reveals without
// touching - and thus without burning - the secret record itself.
//
// A record holds the remaining reveal count plus a copy of the opaque
// ciphertext. Consume hands that copy out while views remain and deletes the
// record on the last view, which the caller then routes through the normal
// exactly-once burn path.
package secretviews

import (
	"context"
	"encoding/json"

	"go.etcd.io/bbolt"

	"github.com/YouSysAdmin/secret-share/internal/domain/store"
)

// Store persists multi-view budgets in one bbolt bucket. It implements
// store.SecretViewsStore.
type Store struct {
	db     *bbolt.DB
	bucket []byte
}

var _ store.SecretViewsStore = (*Store)(nil)

// record is the at-rest schema (json, like every bolt record here).
type record struct {
	Remaining  int    `json:"remaining"`
	Ciphertext string `json:"ciphertext"`
}

// NewStore returns a views store backed by db, persisting into bucket.
func NewStore(db *bbolt.DB, bucket string) *Store {
	return &Store{db: db, bucket: []byte(bucket)}
}

// Put records a budget of remaining reveals for id.
func (s *Store) Put(_ context.Context, id string, remaining int, ciphertext string) error {
	if s == nil || s.db == nil || id == "" || remaining < 1 {
		return nil
	}
	raw, err := json.Marshal(record{Remaining: remaining, Ciphertext: ciphertext})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(s.bucket)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), raw)
	})
}

// Consume atomically decrements id's budget in a single Update txn, so
// concurrent reveals can't overshoot the budget. While views remain it returns
// the stored ciphertext; on the last view it deletes the record and returns
// ("", 0, true) - the caller must then fall through to the real burn path.
func (s *Store) Consume(_ context.Context, id string) (string, int, bool, error) {
	if s == nil || s.db == nil || id == "" {
		return "", 0, false, nil
	}
	var (
		ct        string
		remaining int
		found     bool
	)
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return nil
		}
		var r record
		if err := json.Unmarshal(raw, &r); err != nil {
			// A corrupt record must not make the secret unrevealable: drop it and
			// let the reveal fall through to the normal one-time path.
			return b.Delete([]byte(id))
		}
		found = true
		r.Remaining--
		if r.Remaining <= 0 {
			remaining = 0
			return b.Delete([]byte(id))
		}
		remaining = r.Remaining
		ct = r.Ciphertext
		out, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), out)
	})
	return ct, remaining, found, err
}

// Remaining reports id's current budget without consuming.
func (s *Store) Remaining(_ context.Context, id string) (int, bool, error) {
	if s == nil || s.db == nil || id == "" {
		return 0, false, nil
	}
	var (
		remaining int
		found     bool
	)
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return nil
		}
		var r record
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil
		}
		remaining = r.Remaining
		found = true
		return nil
	})
	return remaining, found, err
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

// List returns every recorded secret id, for orphan cleanup.
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
