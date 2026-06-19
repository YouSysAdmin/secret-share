package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/logger"
	"github.com/YouSysAdmin/secret-share/internal/domain/secrets"
	"github.com/YouSysAdmin/secret-share/internal/server"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the secret-share server",
		RunE:  runServe,
	}
}

func runServe(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")

	cfg, err := env.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	log, err := logger.InitLogger(cfg.Logging.Level, cfg.Logging.Output, cfg.Logging.Format, cfg.Logging.Color)
	if err != nil {
		return err
	}

	rt := &env.Runtime{
		Config:     cfg,
		Log:        log,
		ConfigPath: absPath(cfgPath),
	}

	st, closeStore, err := openStore(rt)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer closeStore()
	log.Info("storage ready", "path", rt.StoreProvider.Path())

	// Background sweeper purges expired secrets (bbolt has no TTL index).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secrets.StartSweeper(ctx, st, cfg.SweepIntervalDuration(), log)

	srv, err := server.New(server.Options{Runtime: rt, Store: st})
	if err != nil {
		return err
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Info("shutting down")
		cancel()
		if err := srv.Shutdown(); err != nil {
			log.Error("shutdown error", "err", err)
		}
	}()

	if err := srv.Start(); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

// absPath resolves p to an absolute path, returning "" for an empty input.
func absPath(p string) string {
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}
