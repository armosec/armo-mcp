// Package telemetry wires up structured logging (zap) and distributed
// tracing (OpenTelemetry) for armo-mcp. It intentionally has no dependency
// on any ARMO-internal logging library so the service stays a standalone,
// externally-buildable module.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	//nolint:staticcheck // SA1019: the Jaeger thrift exporter is the ARMO platform convention. Tempo's distributor accepts traces via Jaeger UDP compact thrift on :6831 and exposes no OTLP receiver (see shared-designs-and-docs architecture/observability.md). Moving to OTLP is a platform-wide decision (all services + a Tempo OTLP receiver), not an armo-mcp change — migrating unilaterally would break trace ingestion.
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Shutdown flushes and stops whatever telemetry provider InitTracer set up.
// It is always safe to call, even when tracing was never enabled (no-op).
type Shutdown func(context.Context) error

// InitLogger builds a production-grade, JSON-encoded zap logger, installs it
// as the global logger (zap.ReplaceGlobals) and redirects the standard
// library's log package (zap.RedirectStdLog) so third-party code that logs
// via "log" is captured too.
func InitLogger(service, env, level string) *zap.Logger {
	cfg := zap.NewProductionConfig()

	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)

	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	cfg.InitialFields = map[string]interface{}{
		"service": service,
		"env":     env,
	}

	logger, err := cfg.Build()
	if err != nil {
		// Fall back to a minimal logger rather than returning nil/panicking;
		// this should not normally happen with a static, valid config.
		logger = zap.NewNop()
	}

	zap.ReplaceGlobals(logger)
	zap.RedirectStdLog(logger)

	return logger
}

// InitTracer configures the global OpenTelemetry tracer provider and text
// map propagator, mirroring cadashboardbe's tracing setup.
//
//   - jaegerHost == ""       -> tracing disabled; returns a nil-safe no-op
//     Shutdown and skips provider setup entirely.
//   - jaegerHost == "stdout" -> spans are exported to stdout (stdouttrace).
//   - otherwise              -> spans are exported to a Jaeger agent at
//     jaegerHost:jaegerPort.
func InitTracer(ctx context.Context, service, env, jaegerHost, jaegerPort string) (Shutdown, error) {
	if jaegerHost == "" {
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := newExporter(jaegerHost, jaegerPort)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			semconv.ServiceNameKey.String(service),
			semconv.DeploymentEnvironmentKey.String(env),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(1.0))),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}

func newExporter(jaegerHost, jaegerPort string) (sdktrace.SpanExporter, error) {
	if jaegerHost == "stdout" {
		return stdouttrace.New(stdouttrace.WithPrettyPrint())
	}

	return jaeger.New(jaeger.WithAgentEndpoint(
		jaeger.WithAgentHost(jaegerHost),
		jaeger.WithAgentPort(jaegerPort),
	))
}

// Tracer is a convenience accessor for a named tracer from the global
// tracer provider, matching the common cadashboardbe usage pattern.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}
