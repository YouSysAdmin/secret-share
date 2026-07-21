package files

import (
	"context"
	"log/slog"
	"time"

	"github.com/YouSysAdmin/secret-share/internal/domain/store"
)

// StartSweeper purges expired files on the given interval until ctx is
// cancelled (bbolt has no TTL index). Mirrors secrets.StartSweeper.
func StartSweeper(ctx context.Context, st *store.Store, interval time.Duration, log *slog.Logger) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, err := st.Files.DeleteExpired(ctx, time.Now())
				if err != nil {
					log.Warn("file sweep failed", "err", err)
					continue
				}
				if n > 0 {
					log.Debug("file sweep: purged expired files", "count", n)
				}
			}
		}
	}()
}
