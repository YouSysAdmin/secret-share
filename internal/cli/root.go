// Package cli is the cobra command tree.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/YouSysAdmin/secret-share/pkg/version"
)

func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           version.AppName,
		Short:         "Share secrets between teams with one-time, expiring links",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	serve := newServeCmd()
	serve.Flags().StringP("config", "c", "", "path to YAML config (default: ./secret-share.yaml)")

	root.AddCommand(serve, newUserCmd(), newVersionCmd())
	return root
}
