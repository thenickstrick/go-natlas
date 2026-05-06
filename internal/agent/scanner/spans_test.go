package scanner_test

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/thenickstrick/go-natlas/internal/agent/scanner"
	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// TestScanEmitsSpan exercises the tracer wiring without invoking nmap. We
// install a SpanRecorder, call Scan with a syntactically valid target and a
// 0-ms timeout so nmap never actually launches under us, and assert that
// the "scan.nmap" span was created with its expected attributes regardless
// of the eventual error path.
func TestScanEmitsSpan(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	// Use a binary that doesn't exist so we don't depend on nmap being
	// installed in the test environment. The tracer wiring still runs to
	// completion regardless of whether the subprocess succeeds.
	sc := scanner.New("/nonexistent-nmap", "", t.TempDir())
	work := &protocol.WorkItem{
		ScanID:     "trace-test",
		Target:     "127.0.0.1",
		ScanReason: protocol.ScanReasonAutomatic,
		AgentConfig: protocol.AgentConfig{
			ScanTimeoutS: 1,
			HostTimeoutS: 1,
		},
	}
	_, _ = sc.Scan(context.Background(), work)

	spans := rec.Ended()
	var found bool
	for _, s := range spans {
		if s.Name() == "scan.nmap" {
			found = true
			attrs := map[string]string{}
			for _, a := range s.Attributes() {
				attrs[string(a.Key)] = a.Value.AsString()
			}
			if attrs["target"] != "127.0.0.1" {
				t.Errorf("scan.nmap span missing target attr: %v", attrs)
			}
			if attrs["scan_id"] != "trace-test" {
				t.Errorf("scan.nmap span missing scan_id attr: %v", attrs)
			}
			break
		}
	}
	if !found {
		t.Fatalf("scan.nmap span was not emitted; got %d spans", len(spans))
	}
}
