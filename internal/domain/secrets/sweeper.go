package secrets

import (
	"context"
	"log/slog"
	"time"

	"github.com/YouSysAdmin/secret-share/internal/domain/store"
)

// StartSweeper runs a background loop that purges expired secrets every
// interval, until ctx is canceled. bbolt has no TTL index, so this is how
// expired secrets get reaped (lazy checks in the handlers are the backstop).
func StartSweeper(ctx context.Context, st *store.Store, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, err := st.Secrets.DeleteExpired(ctx, time.Now())
				if err != nil {
					log.Warn("sweep expired secrets failed", "err", err)
					continue
				}
				if n > 0 {
					log.Debug("swept expired secrets", "count", n)
				}
			}
		}
	}()
}
