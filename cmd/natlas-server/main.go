// natlas-server is the HTTP control plane: it manages users, agents, scope,
// rescans, ingests scan results into OpenSearch, and renders the web UI.
//
// Runtime configuration comes entirely from environment variables (see
// internal/config). Exit codes: 0 = clean shutdown, 1 = startup or runtime
// failure, 2 = config validation failure.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/thenickstrick/go-natlas/internal/config"
	"github.com/thenickstrick/go-natlas/internal/server/app"
	"github.com/thenickstrick/go-natlas/internal/telemetry"
)

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "natlas-server: %v\n", err)
		return 2
	}

	logger := telemetry.NewLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)

	shutdownTel, err := telemetry.Init(ctx, telemetry.Options{
		ServiceName:    "natlas-server",
		ServiceVersion: Version,
		OTLPEndpoint:   cfg.OTel.Endpoint,
		Enabled:        cfg.OTel.Enabled,
		Insecure:       cfg.OTel.Insecure,
	})
	if err != nil {
		slog.ErrorContext(ctx, "telemetry init", "err", err)
		return 1
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTel(sctx); err != nil {
			slog.ErrorContext(sctx, "telemetry shutdown", "err", err)
		}
	}()

	slog.InfoContext(ctx, "natlas-server starting",
		"version", Version,
		"addr", cfg.HTTPAddr,
		"dialect", cfg.Dialect(),
	)

	a, err := app.New(ctx, cfg)
	if err != nil {
		slog.ErrorContext(ctx, "app bootstrap", "err", err)
		return 1
	}
	if err := a.Run(ctx); err != nil {
		slog.ErrorContext(ctx, "server terminated", "err", err)
		return 1
	}
	slog.InfoContext(ctx, "natlas-server stopped")
	return 0
}
