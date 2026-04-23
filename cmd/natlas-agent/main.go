// natlas-agent polls the natlas-server for scan work, invokes nmap, captures
// screenshots, and submits results. Phase 1 stub: loads config, wires telemetry,
// and idles until signalled. The worker pool, HTTP client, nmap invocation,
// and screenshot subsystems are added in later phases.
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
	"github.com/thenickstrick/go-natlas/internal/telemetry"
)

var Version = "dev"

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadAgent()
	if err != nil {
		fmt.Fprintf(os.Stderr, "natlas-agent: %v\n", err)
		return 2
	}

	logger := telemetry.NewLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)

	shutdownTel, err := telemetry.Init(ctx, telemetry.Options{
		ServiceName:    "natlas-agent",
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

	slog.InfoContext(ctx, "natlas-agent starting (phase-1 stub; no scanning yet)",
		"version", Version,
		"server_url", cfg.ServerURL,
		"max_workers", cfg.MaxWorkers,
	)

	<-ctx.Done()
	slog.InfoContext(ctx, "natlas-agent stopped")
	return 0
}
