// Package metrics centralizes the OTel instruments natlas exports. Every
// instrument is wrapped behind a typed recording function so callers don't
// have to know the OTel API surface — they just call ScanCompleted /
// DispatchCounted / ScreenshotCaptured at the appropriate place.
//
// Initialization is lazy + sync.Once-protected: the OTel global meter is
// inspected on first use, after the SDK has been configured by
// telemetry.Init. Instruments captured before SDK init would reference the
// no-op meter forever and silently emit nothing.
//
// Failure modes: instrument construction errors are stashed but never
// fatal. A misconfigured metric is logged once and downgraded to a no-op so
// the application keeps running.
package metrics

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "natlas"

var (
	initOnce sync.Once

	scansTotal       metric.Int64Counter
	scanDuration     metric.Float64Histogram
	dispatchesTotal  metric.Int64Counter
	screenshotsTotal metric.Int64Counter
)

// ensureInit lazily constructs every instrument exactly once. Subsequent
// calls are a sync.Once cache hit.
func ensureInit() {
	initOnce.Do(func() {
		m := otel.Meter(meterName)

		var err error
		scansTotal, err = m.Int64Counter("natlas_scans_total",
			metric.WithDescription("scans completed by an agent, counted per outcome"),
		)
		if err != nil {
			slog.Warn("metrics: scans_total init failed", "err", err)
		}
		scanDuration, err = m.Float64Histogram("natlas_scan_duration_seconds",
			metric.WithDescription("end-to-end agent scan duration (poll → submit)"),
			metric.WithUnit("s"),
		)
		if err != nil {
			slog.Warn("metrics: scan_duration_seconds init failed", "err", err)
		}
		dispatchesTotal, err = m.Int64Counter("natlas_dispatches_total",
			metric.WithDescription("work items dispatched by /api/v1/work, counted per scan_reason"),
		)
		if err != nil {
			slog.Warn("metrics: dispatches_total init failed", "err", err)
		}
		screenshotsTotal, err = m.Int64Counter("natlas_screenshots_total",
			metric.WithDescription("screenshots captured by an agent, counted per service"),
		)
		if err != nil {
			slog.Warn("metrics: screenshots_total init failed", "err", err)
		}
	})
}

// ScanCompleted records the outcome of one full agent dispatch unit. status
// is one of "ok" | "failed" | "timed_out" | "submit_failed" | "cancelled".
// durationS is the total elapsed seconds from work-pickup to submit.
func ScanCompleted(ctx context.Context, status string, durationS float64) {
	ensureInit()
	attrs := metric.WithAttributes(attribute.String("status", status))
	if scansTotal != nil {
		scansTotal.Add(ctx, 1, attrs)
	}
	if scanDuration != nil {
		scanDuration.Record(ctx, durationS, attrs)
	}
}

// DispatchCounted records one /api/v1/work dispatch. reason is one of
// "automatic" | "requested" | "manual" — the same value embedded in
// WorkItem.ScanReason.
func DispatchCounted(ctx context.Context, reason string) {
	ensureInit()
	if dispatchesTotal == nil {
		return
	}
	dispatchesTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

// ScreenshotCaptured records one captured screenshot. service is "HTTP",
// "HTTPS", or "VNC" matching the screenshots package constants.
func ScreenshotCaptured(ctx context.Context, service string) {
	ensureInit()
	if screenshotsTotal == nil {
		return
	}
	screenshotsTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("service", service)))
}
