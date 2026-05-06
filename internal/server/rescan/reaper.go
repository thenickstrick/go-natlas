// Package rescan owns operational pieces of the rescan queue that don't
// belong inside an HTTP handler — currently just the stale-dispatch reaper.
//
// Why a reaper exists: when an agent picks up a rescan it dispatches the row
// (sets dispatched_at and scan_id). If the agent crashes, network blips, or
// the result XML is malformed, the row sits in "dispatched but never
// completed" state forever, blocking that target from being rescannable by a
// new request (the unique scan_id index would conflict, and operators would
// see a stuck UI).
//
// Reaper.Run periodically clears dispatched_at + scan_id on rows that have
// been dispatched longer than Threshold without completing. The next time an
// agent polls /api/v1/work, the row appears as pending again and gets a
// fresh scan_id.
package rescan

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/thenickstrick/go-natlas/internal/server/data"
)

var tracer = otel.Tracer("natlas/server/rescan")

// Reaper periodically requeues stuck rescans.
//
// The zero value is not usable; construct via New.
type Reaper struct {
	store     data.Store
	interval  time.Duration
	threshold time.Duration
}

// Options tunes the reaper. Defaults are conservative: 60s tick + a 10-minute
// stale window. An operator running short-timeout scans can shrink Threshold;
// long, multi-hour scans should bump it.
type Options struct {
	Interval  time.Duration
	Threshold time.Duration
}

// New returns a Reaper. Interval and Threshold default to sane values only
// when zero — a negative Threshold is a deliberate override (tests use it to
// land the cutoff in the future regardless of sub-millisecond clock skew
// against SQLite's strftime).
func New(store data.Store, opts Options) *Reaper {
	if opts.Interval <= 0 {
		opts.Interval = time.Minute
	}
	if opts.Threshold == 0 {
		opts.Threshold = 10 * time.Minute
	}
	return &Reaper{store: store, interval: opts.Interval, threshold: opts.Threshold}
}

// Run blocks until ctx is cancelled, calling Reap every Interval. The first
// reap fires immediately on startup so a server that crash-restarted while a
// dispatch was outstanding doesn't sit on a stuck row for a full Interval.
func (r *Reaper) Run(ctx context.Context) error {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	if err := r.Reap(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.WarnContext(ctx, "rescan reaper: initial sweep failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := r.Reap(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.WarnContext(ctx, "rescan reaper: sweep failed", "err", err)
			}
		}
	}
}

// Reap performs one sweep. Exposed for tests + manual invocations.
func (r *Reaper) Reap(ctx context.Context) error {
	ctx, span := tracer.Start(ctx, "rescan.reap",
		// The cutoff attribute helps operators correlate "I expected this row
		// to be reaped — what cutoff did the sweep use?" against the timestamp
		// in the row.
	)
	defer span.End()

	cutoff := time.Now().UTC().Add(-r.threshold)
	span.SetAttributes(attribute.String("cutoff", cutoff.Format(time.RFC3339Nano)))

	ids, err := r.store.RescanTaskReapStale(ctx, cutoff)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	span.SetAttributes(attribute.Int("requeued", len(ids)))
	if len(ids) > 0 {
		slog.InfoContext(ctx, "rescan reaper: requeued stale tasks",
			"count", len(ids), "cutoff", cutoff, "ids", ids)
	}
	return nil
}
