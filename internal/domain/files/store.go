// Package files adapts the file model to HTTP + bbolt: an encrypted-file
// counterpart to the secrets domain with the same lifecycle (create with
// expiry, reveal exactly once, background sweep). The server only ever holds
// opaque ciphertext - the browser encrypts filename and content together and
// the key never arrives here.
package files

import (
	"context"
	"encoding/json"
	"time"

	"go.etcd.io/bbolt"

	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/models/file"
)

// Store is the bbolt-backed file store. It implements store.FileStore.
type Store struct {
	db     *bbolt.DB
	bucket []byte
}

var _ store.FileStore = (*Store)(nil)

// NewStore returns a file store backed by db, persisting into bucket.
func NewStore(db *bbolt.DB, bucket string) *Store {
	return &Store{db: db, bucket: []byte(bucket)}
}

// Create stores a new file.
func (s *Store) Create(_ context.Context, f *file.File) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(s.bucket)
		if err != nil {
			return err
		}
		return b.Put([]byte(f.ID), raw)
	})
}

// GetMeta returns the file for id without consuming it, or (nil, nil) when
// absent or already expired (an expired record is treated as gone even before
// the sweeper catches it).
func (s *Store) GetMeta(_ context.Context, id string) (*file.File, error) {
	var f *file.File
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return nil
		}
		var rec file.File
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if rec.IsExpired(time.Now()) {
			return nil
		}
		f = &rec
		return nil
	})
	return f, err
}

// GetAndBurn atomically returns the file and deletes it in one Update txn -
// the exactly-once primitive. Returns (nil, nil) when already gone or expired.
func (s *Store) GetAndBurn(_ context.Context, id string) (*file.File, error) {
	var f *file.File
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		key := []byte(id)
		raw := b.Get(key)
		if raw == nil {
			return nil
		}
		var rec file.File
		if err := json.Unmarshal(raw, &rec); err != nil {
			return b.Delete(key)
		}
		if err := b.Delete(key); err != nil {
			return err
		}
		if rec.IsExpired(time.Now()) {
			return nil
		}
		f = &rec
		return nil
	})
	return f, err
}

// Delete removes the file for id (no-op if absent).
func (s *Store) Delete(_ context.Context, id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	})
}

// DeleteExpired purges files whose ExpiresAt is at or before now.
func (s *Store) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	removed := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b == nil {
			return nil
		}
		var expired [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec file.File
			if err := json.Unmarshal(v, &rec); err != nil {
				expired = append(expired, append([]byte(nil), k...))
				return nil
			}
			if rec.IsExpired(now) {
				expired = append(expired, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range expired {
			if err := b.Delete(k); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}
