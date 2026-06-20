package users

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"

	usermodel "github.com/YouSysAdmin/secret-share/internal/models/user"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "test.db"), 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte("users"))
		return e
	}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return NewStore(db, "users")
}

func TestRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if got, err := s.Get(ctx, "nobody@corp.com"); err != nil || got != nil {
		t.Fatalf("Get(absent) = (%v,%v), want (nil,nil)", got, err)
	}

	p := &usermodel.User{Email: "Admin@Corp.com", Role: usermodel.RoleAdmin, Source: usermodel.SourceLocal, Enabled: true}
	if err := s.Upsert(ctx, p); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if p.Email != "admin@corp.com" {
		t.Errorf("Upsert should normalize email, got %q", p.Email)
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Error("Upsert should stamp CreatedAt/UpdatedAt")
	}

	// Get is case-insensitive on email.
	got, err := s.Get(ctx, "ADMIN@corp.com")
	if err != nil || got == nil {
		t.Fatalf("Get = (%v,%v)", got, err)
	}
	if got.Role != usermodel.RoleAdmin {
		t.Errorf("role = %q", got.Role)
	}

	created := got.CreatedAt
	time.Sleep(2 * time.Millisecond)

	// Update preserves CreatedAt, bumps UpdatedAt.
	got.Role = usermodel.RoleUser
	if err := s.Upsert(ctx, got); err != nil {
		t.Fatalf("Upsert update: %v", err)
	}
	reread, _ := s.Get(ctx, "admin@corp.com")
	if !reread.CreatedAt.Equal(created) {
		t.Error("CreatedAt should be preserved across updates")
	}
	if !reread.UpdatedAt.After(created) {
		t.Error("UpdatedAt should advance")
	}
}

func TestCountByRoleAndDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mustUpsert(t, s, "a@corp.com", usermodel.RoleAdmin)
	mustUpsert(t, s, "b@corp.com", usermodel.RoleAdmin)
	mustUpsert(t, s, "c@corp.com", usermodel.RoleUser)

	if n, _ := s.CountByRole(ctx, usermodel.RoleAdmin); n != 2 {
		t.Errorf("admins = %d, want 2", n)
	}
	if n, _ := s.CountByRole(ctx, usermodel.RoleUser); n != 1 {
		t.Errorf("users = %d, want 1", n)
	}

	ps, _ := s.List(ctx)
	if len(ps) != 3 {
		t.Errorf("list = %d, want 3", len(ps))
	}

	if err := s.Delete(ctx, "b@corp.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if n, _ := s.CountByRole(ctx, usermodel.RoleAdmin); n != 1 {
		t.Errorf("admins after delete = %d, want 1", n)
	}
}

func mustUpsert(t *testing.T, s *Store, email string, role usermodel.Role) {
	t.Helper()
	if err := s.Upsert(context.Background(), &usermodel.User{Email: email, Role: role, Enabled: true, Source: usermodel.SourceOIDC}); err != nil {
		t.Fatalf("Upsert(%s): %v", email, err)
	}
}
