package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestHTTPMiddleware(t *testing.T) {
	// Step 1: Create metrics and a test handler
	m := New()

	// Create a simple test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Wrap with middleware
	wrappedHandler := m.HTTPMiddleware(testHandler)

	// Make a test request
	req := httptest.NewRequest("GET", "/mcp", nil)
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	// Verify request was successful
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	// Assert http_requests_total was incremented
	count := testutil.CollectAndCount(m.Reg, "http_requests_total")
	if count != 1 {
		t.Errorf("expected 1 http_requests_total metric, got %d", count)
	}

	// Assert http_request_duration_seconds was recorded
	durCount := testutil.CollectAndCount(m.Reg, "http_request_duration_seconds")
	if durCount != 1 {
		t.Errorf("expected 1 http_request_duration_seconds metric, got %d", durCount)
	}
}

func TestToolCall(t *testing.T) {
	m := New()

	// Call ToolCall
	m.ToolCall("query_x", "ok")

	// Assert armomcp_tool_calls_total was incremented
	count := testutil.CollectAndCount(m.Reg, "armomcp_tool_calls_total")
	if count != 1 {
		t.Errorf("expected 1 armomcp_tool_calls_total metric, got %d", count)
	}
}

func TestRateLimited(t *testing.T) {
	m := New()

	// Call RateLimited
	m.RateLimited()

	// Assert armomcp_ratelimit_rejected_total was incremented
	count := testutil.CollectAndCount(m.Reg, "armomcp_ratelimit_rejected_total")
	if count != 1 {
		t.Errorf("expected 1 armomcp_ratelimit_rejected_total metric, got %d", count)
	}
}

func TestCacheEvent(t *testing.T) {
	m := New()

	// Call CacheEvent
	m.CacheEvent("hit")

	// Assert armomcp_cache_events_total was incremented
	count := testutil.CollectAndCount(m.Reg, "armomcp_cache_events_total")
	if count != 1 {
		t.Errorf("expected 1 armomcp_cache_events_total metric, got %d", count)
	}
}

func TestBackendRequest(t *testing.T) {
	m := New()

	// Call BackendRequest
	m.BackendRequest("ok")

	// Assert armomcp_backend_requests_total was incremented
	count := testutil.CollectAndCount(m.Reg, "armomcp_backend_requests_total")
	if count != 1 {
		t.Errorf("expected 1 armomcp_backend_requests_total metric, got %d", count)
	}
}

func TestHandler(t *testing.T) {
	m := New()

	// Verify Handler returns a valid http.Handler
	handler := m.Handler()
	if handler == nil {
		t.Error("Handler() returned nil")
	}

	// Test that it can handle a request
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should return 200
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}
