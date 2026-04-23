// Package telemetry wires OpenTelemetry traces and metrics over OTLP gRPC and
// provides a trace-aware slog handler that attaches trace_id / span_id to every
// log emitted with a context carrying a live span.
//
// All exports are best-effort: when disabled, Init installs no-op providers and
// the returned ShutdownFunc is a harmless no-op. Code that emits telemetry
// (tracers, meters, loggers) must therefore be safe to call unconditionally.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Options configures the OTel SDK bootstrap.
type Options struct {
	ServiceName    string
	ServiceVersion string
	OTLPEndpoint   string // host:port, e.g. "otel:4317"
	Enabled        bool
	Insecure       bool // grpc plaintext
}

// ShutdownFunc flushes and shuts down all providers. Safe to call multiple times.
type ShutdownFunc func(context.Context) error

// Init installs OTel providers on the global otel package and returns a shutdown
// hook the caller should defer. When Enabled is false, Init wires only the text
// map propagator (so inbound trace context is still honored) and returns a no-op.
func Init(ctx context.Context, opts Options) (ShutdownFunc, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	if !opts.Enabled {
		return noopShutdown, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(opts.ServiceName),
			semconv.ServiceVersion(opts.ServiceVersion),
		),
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithProcess(),
		resource.WithOS(),
		resource.WithContainer(),
	)
	if err != nil {
		return nil, fmt.Errorf("telemetry resource: %w", err)
	}

	traceOpts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(opts.OTLPEndpoint)}
	metricOpts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(opts.OTLPEndpoint)}
	if opts.Insecure {
		traceOpts = append(traceOpts, otlptracegrpc.WithInsecure())
		metricOpts = append(metricOpts, otlpmetricgrpc.WithInsecure())
	}

	traceExp, err := otlptracegrpc.New(ctx, traceOpts...)
	if err != nil {
		return nil, fmt.Errorf("otlp trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	metricExp, err := otlpmetricgrpc.New(ctx, metricOpts...)
	if err != nil {
		// Best-effort: tear the trace provider down so we don't leak a batcher.
		_ = tp.Shutdown(context.Background())
		return nil, fmt.Errorf("otlp metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	return func(ctx context.Context) error {
		var errs []error
		if err := tp.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("tracer provider: %w", err))
		}
		if err := mp.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("meter provider: %w", err))
		}
		return errors.Join(errs...)
	}, nil
}

func noopShutdown(context.Context) error { return nil }

// NewLogger returns an slog logger. When a record is emitted via a *Context
// method (InfoContext, ErrorContext, etc.) and the context carries a live span,
// trace_id and span_id are attached to the record.
func NewLogger(levelStr, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(levelStr)}
	var inner slog.Handler
	switch strings.ToLower(format) {
	case "text":
		inner = slog.NewTextHandler(os.Stdout, opts)
	default:
		inner = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(&traceAwareHandler{Handler: inner})
}

type traceAwareHandler struct {
	slog.Handler
}

func (h *traceAwareHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		if sc := trace.SpanFromContext(ctx).SpanContext(); sc.IsValid() {
			r.AddAttrs(
				slog.String("trace_id", sc.TraceID().String()),
				slog.String("span_id", sc.SpanID().String()),
			)
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h *traceAwareHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceAwareHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *traceAwareHandler) WithGroup(name string) slog.Handler {
	return &traceAwareHandler{Handler: h.Handler.WithGroup(name)}
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
