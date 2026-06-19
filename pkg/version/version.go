// Package version holds build-time identity.
// Version is overridden via
// -ldflags "-X github.com/YouSysAdmin/secret-share/pkg/version.Version=..."
package version

const AppName = "secret-share"

var Version = "devel"
