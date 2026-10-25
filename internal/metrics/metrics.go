package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds a dedicated Prometheus registry and metric vectors.
type Metrics struct {
	Reg *prometheus.Registry

	httpRequestsTotal      *prometheus.CounterVec
	httpRequestDuration    *prometheus.HistogramVec
	toolCallsTotal         *prometheus.CounterVec
	rateLimitRejectedTotal prometheus.Counter
	cacheEventsTotal       *prometheus.CounterVec
	backendRequestsTotal   *prometheus.CounterVec
}

// New creates and returns a new Metrics instance with a dedicated registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	factory := promauto.With(reg)

	m := &Metrics{
		Reg: reg,
		httpRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"path", "method"},
		),
		httpRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"path", "method"},
		),
		toolCallsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "armomcp_tool_calls_total",
				Help: "Total number of tool calls",
			},
			[]string{"tool", "result"},
		),
		rateLimitRejectedTotal: factory.NewCounter(prometheus.CounterOpts{
			Name: "armomcp_ratelimit_rejected_total",
			Help: "Total number of rate-limited requests",
		}),
		cacheEventsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "armomcp_cache_events_total",
				Help: "Total number of cache events",
			},
			[]string{"event"},
		),
		backendRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "armomcp_backend_requests_total",
				Help: "Total number of backend requests",
			},
			[]string{"result"},
		),
	}

	return m
}

// Handler returns an HTTP handler for the Prometheus registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Reg, promhttp.HandlerOpts{})
}

// HTTPMiddleware wraps an HTTP handler and records metrics for requests.
func (m *Metrics) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start).Seconds()

		label := routeLabel(r.URL.Path)
		m.httpRequestsTotal.WithLabelValues(label, r.Method).Inc()
		m.httpRequestDuration.WithLabelValues(label, r.Method).Observe(duration)
	})
}

// routeLabel bounds the cardinality of the "path" label by collapsing any
// path outside the known route set down to "other", so scanners and
// unmatched requests can't mint unbounded Prometheus time series.
func routeLabel(p string) string {
	switch p {
	case "/mcp", "/healthz", "/metrics":
		return p
	default:
		return "other"
	}
}

// ToolCall records a tool call metric.
func (m *Metrics) ToolCall(tool, result string) {
	m.toolCallsTotal.WithLabelValues(tool, result).Inc()
}

// RateLimited records a rate-limited request.
func (m *Metrics) RateLimited() {
	m.rateLimitRejectedTotal.Inc()
}

// CacheEvent records a cache event.
func (m *Metrics) CacheEvent(event string) {
	m.cacheEventsTotal.WithLabelValues(event).Inc()
}

// BackendRequest records a backend request result.
func (m *Metrics) BackendRequest(result string) {
	m.backendRequestsTotal.WithLabelValues(result).Inc()
}
