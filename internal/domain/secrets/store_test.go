package secrets

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.etcd.io/bbolt"

	"github.com/YouSysAdmin/secret-share/internal/models/secret"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "test.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte("secrets"))
		return e
	}); err != nil {
		t.Fatal(err)
	}
	return NewStore(db, "secrets")
}

func mkSecret(id string) *secret.Secret {
	return &secret.Secret{
		ID:         id,
		Ciphertext: "blob-" + id,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
}

func TestGetMetaDoesNotBurn(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Create(ctx, mkSecret("a")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got, err := s.GetMeta(ctx, "a")
		if err != nil || got == nil {
			t.Fatalf("GetMeta should keep returning the secret: %v %v", got, err)
		}
	}
}

func TestGetAndBurnIsExactlyOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Create(ctx, mkSecret("b")); err != nil {
		t.Fatal(err)
	}

	const racers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			got, err := s.GetAndBurn(ctx, "b")
			if err != nil {
				return
			}
			if got != nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("exactly one reveal should win, got %d", wins)
	}
	if got, _ := s.GetMeta(ctx, "b"); got != nil {
		t.Fatal("secret should be gone after burn")
	}
}

func TestCreateRejectsDuplicateID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Create(ctx, mkSecret("dup")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, mkSecret("dup")); err == nil {
		t.Fatal("expected an id-collision error")
	}
}

func TestDeleteExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	fresh := mkSecret("fresh")
	stale := mkSecret("stale")
	stale.ExpiresAt = time.Now().Add(-time.Minute)
	if err := s.Create(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, stale); err != nil {
		t.Fatal(err)
	}

	n, err := s.DeleteExpired(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 expired purged, got %d", n)
	}
	if got, _ := s.GetMeta(ctx, "stale"); got != nil {
		t.Fatal("stale secret should be purged")
	}
	if got, _ := s.GetMeta(ctx, "fresh"); got == nil {
		t.Fatal("fresh secret should remain")
	}
}
