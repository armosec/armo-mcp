package telemetry

import (
	"context"
	"testing"
)

func TestInitTracerNoopWhenNoJaegerHost(t *testing.T) {
	ctx := context.Background()

	shutdown, err := InitTracer(ctx, "armo-mcp", "test", "", "")
	if err != nil {
		t.Fatalf("InitTracer() error = %v, want nil", err)
	}
	if shutdown == nil {
		t.Fatal("InitTracer() shutdown = nil, want non-nil no-op Shutdown")
	}
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown(ctx) = %v, want nil", err)
	}
}

func TestInitLoggerReturnsNonNilLogger(t *testing.T) {
	logger := InitLogger("armo-mcp", "test", "info")
	if logger == nil {
		t.Fatal("InitLogger() = nil, want non-nil *zap.Logger")
	}
}
