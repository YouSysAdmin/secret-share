// Package database declares the engine lifecycle abstraction the bbolt backend
// implements. Per-domain persistence (users, secrets) lives in the typed stores
// under internal/domain/<thing>/, which the backend's BindProvider wires up.
package database

import "io"

// Database is the lifecycle surface the storage backend exposes plus the
// bucket-name accessors the domain stores read through.
type Database interface {
	// Close releases backend resources. A second call may be a no-op.
	Close() error

	// Path returns the on-disk location (the bbolt file path).
	Path() string

	// Backup writes a consistent snapshot of the whole store to w and returns the
	// bytes written (bbolt's Tx.WriteTo - a hot backup).
	Backup(w io.Writer) (int64, error)

	// GetSecretsBucketName returns the bucket/namespace where secrets live.
	GetSecretsBucketName() string

	// GetUsersBucketName returns the bucket/namespace where console
	// users (private-mode identities) live.
	GetUsersBucketName() string

	// GetSecretVisibilityBucketName returns the bucket/namespace recording which
	// secrets are private (require a session to reveal).
	GetSecretVisibilityBucketName() string
}
