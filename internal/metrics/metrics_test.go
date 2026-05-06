package metrics_test

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	natlasmetrics "github.com/thenickstrick/go-natlas/internal/metrics"
)

// findMetric digs into the resource-scoped metrics for a named instrument.
func findMetric(rm *metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

// One test, four instruments. The metrics package init runs exactly once
// across the test binary lifetime — so we install the test provider BEFORE
// the first recording call, and route every assertion through this single
// test. Splitting would yield "second test sees no metrics" because the
// first test's provider would already own the captured instruments.
func TestInstrumentsRecord(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(previous)
		_ = provider.Shutdown(context.Background())
	})

	ctx := context.Background()
	natlasmetrics.ScanCompleted(ctx, "ok", 4.2)
	natlasmetrics.ScanCompleted(ctx, "failed", 1.0)
	natlasmetrics.DispatchCounted(ctx, "automatic")
	natlasmetrics.DispatchCounted(ctx, "requested")
	natlasmetrics.ScreenshotCaptured(ctx, "HTTP")
	natlasmetrics.ScreenshotCaptured(ctx, "VNC")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, name := range []string{
		"natlas_scans_total",
		"natlas_scan_duration_seconds",
		"natlas_dispatches_total",
		"natlas_screenshots_total",
	} {
		if got := findMetric(&rm, name); got == nil {
			t.Errorf("%s missing from collected metrics", name)
		}
	}
}
