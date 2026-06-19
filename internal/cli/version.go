package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/YouSysAdmin/secret-share/pkg/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the binary version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", version.AppName, version.Version)
			return nil
		},
	}
}
