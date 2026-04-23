// Package worker owns the agent's concurrency model. A single poller
// goroutine fetches work whenever a worker slot frees up; N workers execute
// scans and submit results. Graceful shutdown: cancelling the caller's
// context stops the poller immediately and signals workers to finish their
// current scan (bounded by AgentConfig.ScanTimeoutS) before exiting.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/thenickstrick/go-natlas/internal/agent/submit"
	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// Scanner is the subset of *scanner.Scanner that the Pool uses. Kept as an
// interface so tests can inject stubs without invoking nmap.
type Scanner interface {
	Scan(ctx context.Context, work *protocol.WorkItem) (*protocol.Result, error)
}

// Config captures the runtime knobs the pool needs. The fields here are a
// subset of config.Agent — main.go adapts.
type Config struct {
	MaxWorkers     int
	AgentVersion   string
	AgentIDLogTag  string        // what to stamp in slog and result.Agent; typically cfg.AgentID
	PollBackoff    time.Duration // base delay when GetWork returns no-scope / transient error
	PollBackoffMax time.Duration
}

// Pool glues the HTTP client to the scanner via a bounded work channel.
type Pool struct {
	cfg     Config
	client  *submit.Client
	scanner Scanner
}

// New returns a Pool. Call Run to start it.
func New(cfg Config, client *submit.Client, sc Scanner) *Pool {
	if cfg.MaxWorkers < 1 {
		cfg.MaxWorkers = 1
	}
	if cfg.PollBackoff <= 0 {
		cfg.PollBackoff = 2 * time.Second
	}
	if cfg.PollBackoffMax <= 0 {
		cfg.PollBackoffMax = 60 * time.Second
	}
	if cfg.AgentIDLogTag == "" {
		cfg.AgentIDLogTag = "anonymous"
	}
	return &Pool{cfg: cfg, client: client, scanner: sc}
}

// Run starts the poller + workers and blocks until ctx is cancelled. Returns
// ctx.Err() on shutdown; only a truly exceptional internal error returns
// something else (currently: none).
func (p *Pool) Run(ctx context.Context) error {
	workCh := make(chan *protocol.WorkItem)
	var wg sync.WaitGroup

	// Workers
	for i := 0; i < p.cfg.MaxWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.worker(ctx, id, workCh)
		}(i)
	}

	// Poller
	pollErr := p.poll(ctx, workCh)

	// Signal workers to drain and wait.
	close(workCh)
	wg.Wait()

	if pollErr != nil && !errors.Is(pollErr, context.Canceled) && !errors.Is(pollErr, context.DeadlineExceeded) {
		return pollErr
	}
	return nil
}

// poll runs until ctx is done. It keeps the channel fed and, crucially, only
// fetches new work when a worker is actually free — otherwise we'd race the
// server's rescan queue into over-dispatch.
func (p *Pool) poll(ctx context.Context, workCh chan<- *protocol.WorkItem) error {
	backoff := p.cfg.PollBackoff
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		work, err := p.client.GetWork(ctx, "")
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// 404 / 5xx transient / DNS. Log and back off.
			slog.WarnContext(ctx, "agent: getwork failed; backing off", "err", err, "sleep", backoff.String())
			if waitErr := sleepCtx(ctx, backoff); waitErr != nil {
				return waitErr
			}
			backoff = minDuration(backoff*2, p.cfg.PollBackoffMax)
			continue
		}
		// Successful fetch resets backoff.
		backoff = p.cfg.PollBackoff

		select {
		case <-ctx.Done():
			return ctx.Err()
		case workCh <- work:
			// A worker will pick this up immediately (channel is unbuffered).
			// The send completes when a worker is ready; that's our natural
			// back-pressure — the next GetWork only happens once the channel
			// hand-off has succeeded.
		}
	}
}

// worker executes scans and submits results.
func (p *Pool) worker(ctx context.Context, id int, workCh <-chan *protocol.WorkItem) {
	for work := range workCh {
		p.executeOne(ctx, id, work)
	}
}

func (p *Pool) executeOne(ctx context.Context, workerID int, work *protocol.WorkItem) {
	slog.InfoContext(ctx, "agent: scanning",
		"worker", workerID,
		"scan_id", work.ScanID,
		"target", work.Target,
		"reason", work.ScanReason,
	)

	result, err := p.scanner.Scan(ctx, work)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			slog.InfoContext(ctx, "agent: scan cancelled (shutdown)", "scan_id", work.ScanID)
			return
		}
		slog.ErrorContext(ctx, "agent: scan failed",
			"worker", workerID,
			"scan_id", work.ScanID,
			"target", work.Target,
			"err", err,
		)
		return
	}

	// Copy dispatcher fields onto the result so the server can correlate.
	result.ScanID = work.ScanID
	result.ScanReason = work.ScanReason
	result.Tags = work.Tags
	result.Agent = p.cfg.AgentIDLogTag
	result.AgentVersion = p.cfg.AgentVersion

	submitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := p.client.SubmitResult(submitCtx, result); err != nil {
		slog.ErrorContext(ctx, "agent: submit failed",
			"worker", workerID,
			"scan_id", work.ScanID,
			"err", err,
		)
		return
	}
	slog.InfoContext(ctx, "agent: scan submitted",
		"worker", workerID,
		"scan_id", work.ScanID,
		"target", result.Target,
		"is_up", result.IsUp,
		"ports", result.PortCount,
		"elapsed_s", result.ElapsedS,
	)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
