// natlas-agent polls the natlas-server control plane for scan work, invokes
// nmap, and submits results. Exit codes: 0 = clean shutdown, 1 = runtime
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

	"github.com/thenickstrick/go-natlas/internal/agent/scanner"
	"github.com/thenickstrick/go-natlas/internal/agent/submit"
	"github.com/thenickstrick/go-natlas/internal/agent/worker"
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

	client, err := submit.New(submit.Config{
		ServerURL:      cfg.ServerURL,
		AgentID:        cfg.AgentID,
		Token:          cfg.Token,
		UserAgent:      "natlas-agent/" + Version,
		RequestTimeout: cfg.RequestTimeout,
		MaxRetries:     10,
		BackoffBase:    time.Second,
		BackoffCap:     time.Minute,
	})
	if err != nil {
		slog.ErrorContext(ctx, "agent: http client", "err", err)
		return 1
	}

	sc := scanner.New("" /* nmap from PATH */, "" /* no custom services yet */, cfg.DataDir)

	pool := worker.New(worker.Config{
		MaxWorkers:     cfg.MaxWorkers,
		AgentVersion:   Version,
		AgentIDLogTag:  orDefault(cfg.AgentID, "anonymous"),
		PollBackoff:    2 * time.Second,
		PollBackoffMax: time.Minute,
	}, client, sc)

	slog.InfoContext(ctx, "natlas-agent starting",
		"version", Version,
		"server_url", cfg.ServerURL,
		"max_workers", cfg.MaxWorkers,
		"agent_id", orDefault(cfg.AgentID, "anonymous"),
	)

	if err := pool.Run(ctx); err != nil {
		slog.ErrorContext(ctx, "agent: pool exited with error", "err", err)
		return 1
	}
	slog.InfoContext(ctx, "natlas-agent stopped")
	return 0
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
