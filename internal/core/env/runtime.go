package env

import (
	"log/slog"
	"time"

	"go.etcd.io/bbolt"

	"github.com/YouSysAdmin/secret-share/internal/core/oidc"
	"github.com/YouSysAdmin/secret-share/internal/database"
)

// Runtime is the server-scoped bag of dependencies. Built once in cli/serve.go
// and handed to every domain Handler. The aggregate store.Store is NOT here - it
// is passed alongside Runtime in Handler{Runtime, Store} to avoid an import cycle.
type Runtime struct {
	Config *Config
	Log    *slog.Logger

	// ConfigPath is the resolved --config path ("" when configured purely via env).
	ConfigPath string

	// DB is the raw bbolt handle for domain-store transactions. StoreProvider is
	// the lifecycle surface (path/backup/close + bucket names).
	DB            *bbolt.DB
	StoreProvider database.Database

	// Auth (private mode). SessionSecret keys the HMAC session cookie and the
	// at-rest secretbox seal; SessionTTL is the cookie lifetime. Both are zero
	// when auth is disabled. OIDC is the SSO provider registry (nil when no
	// providers are configured).
	SessionSecret []byte
	SessionTTL    time.Duration
	OIDC          *oidc.Registry
}
