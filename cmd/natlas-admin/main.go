// natlas-admin is the operator CLI for the natlas control plane: user and
// agent provisioning, scope CRUD + bulk import/export, and uploading the
// custom nmap services database.
//
// Configuration: env-driven, identical to natlas-server's DB envvars
// (POSTGRES_URL or SQLITE_PATH). The CLI does not touch OpenSearch, the
// object store, or sessions.
//
// Caveat: scope mutations made via this CLI are not picked up by a running
// natlas-server until restart — the in-memory ScopeManager loads at boot.
// Use the web /admin/scope page for hot updates; use this CLI for batch
// imports and automation.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/thenickstrick/go-natlas/internal/config"
	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/telemetry"
)

// Version is set via -ldflags at build time.
var Version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		// Cobra already printed the error; just exit non-zero.
		os.Exit(1)
	}
}

// adminEnv is the dependency handle every subcommand reuses. Lazily
// constructed by openStore when the subcommand actually needs DB access.
type adminEnv struct {
	cfg   *config.Admin
	store data.Store
}

// openStore connects to the configured backend on first use and caches the
// handle for the lifetime of the command. Callers are expected to defer
// e.close().
func (e *adminEnv) openStore(ctx context.Context) (data.Store, error) {
	if e.store != nil {
		return e.store, nil
	}
	var (
		store data.Store
		err   error
	)
	switch e.cfg.Dialect() {
	case "postgres":
		store, err = data.NewPostgresStore(ctx, e.cfg.Postgres.URL)
	case "sqlite":
		store, err = data.NewSQLiteStore(ctx, e.cfg.SQLite.Path)
	default:
		return nil, errors.New("no database configured")
	}
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	e.store = store
	return store, nil
}

func (e *adminEnv) close() {
	if e.store != nil {
		e.store.Close()
		e.store = nil
	}
}

func newRootCmd() *cobra.Command {
	env := &adminEnv{}

	root := &cobra.Command{
		Use:           "natlas-admin",
		Short:         "Operator CLI for the natlas control plane",
		SilenceUsage:  true, // Don't dump usage on every runtime error.
		SilenceErrors: true, // We print our own errors via slog.
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadAdmin()
			if err != nil {
				return err
			}
			env.cfg = cfg
			slog.SetDefault(telemetry.NewLogger(cfg.LogLevel, cfg.LogFormat))
			return nil
		},
		PersistentPostRun: func(_ *cobra.Command, _ []string) {
			env.close()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	root.AddCommand(
		newVersionCmd(),
		newUserCmd(env),
		newAgentCmd(env),
		newScopeCmd(env),
		newServicesCmd(env),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the natlas-admin version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "natlas-admin %s\n", Version)
		},
	}
}
