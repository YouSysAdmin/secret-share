package env

import (
	"log/slog"

	"go.etcd.io/bbolt"

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
}
