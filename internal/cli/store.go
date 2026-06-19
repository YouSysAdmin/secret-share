package cli

import (
	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/database/boltkv"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
)

// openStore opens the bbolt store, wires rt.DB/StoreProvider and the aggregate
// store.Store, and returns a close func the caller must invoke.
func openStore(rt *env.Runtime) (*store.Store, func() error, error) {
	kv, err := boltkv.Open(rt.Config.Database.Path)
	if err != nil {
		return nil, nil, err
	}
	st := &store.Store{}
	boltkv.BindProvider(rt, st, kv)
	return st, kv.Close, nil
}
