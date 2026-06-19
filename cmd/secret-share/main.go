package main

import (
	"log/slog"
	"os"

	"github.com/YouSysAdmin/secret-share/internal/cli"
)

func main() {
	if err := cli.NewRoot().Execute(); err != nil {
		slog.Error("command failed", "err", err)
		os.Exit(1)
	}
}
