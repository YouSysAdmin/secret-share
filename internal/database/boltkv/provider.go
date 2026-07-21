package boltkv

import (
	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/domain/files"
	"github.com/YouSysAdmin/secret-share/internal/domain/secrets"
	"github.com/YouSysAdmin/secret-share/internal/domain/secretviews"
	"github.com/YouSysAdmin/secret-share/internal/domain/secretvis"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/domain/users"
)

// BindProvider wires an already-open boltkv store into the Runtime and the
// aggregate store.Store: Runtime gains the raw DB handle + StoreProvider; the
// aggregate Store gets the boltkv implementation of the secret store. The caller
// still owns kv and Close()s it at shutdown.
func BindProvider(rt *env.Runtime, st *store.Store, kv *Store) {
	rt.DB = kv.DB()
	rt.StoreProvider = kv

	st.Secrets = secrets.NewStore(kv.DB(), kv.GetSecretsBucketName())
	st.Users = users.NewStore(kv.DB(), kv.GetUsersBucketName())
	st.Visibility = secretvis.NewStore(kv.DB(), kv.GetSecretVisibilityBucketName())
	st.Views = secretviews.NewStore(kv.DB(), kv.GetSecretViewsBucketName())
	st.Files = files.NewStore(kv.DB(), kv.GetFilesBucketName())
}
