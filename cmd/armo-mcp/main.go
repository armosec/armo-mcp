package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/auth"
	"github.com/armosec/armo-mcp/internal/cache"
	"github.com/armosec/armo-mcp/internal/config"
	"github.com/armosec/armo-mcp/internal/limit"
	"github.com/armosec/armo-mcp/internal/metrics"
	"github.com/armosec/armo-mcp/internal/telemetry"
	"github.com/armosec/armo-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.uber.org/zap"
)

const version = "0.1.0"

func main() {
	stdio := flag.Bool("stdio", false, "run over stdio for a local MCP host (single-tenant; creds from ARMO_CUSTOMER_GUID/ARMO_ACCESS_KEY env)")
	flag.Parse()

	cfg := config.Load()
	// An unparseable setting stops startup on either transport. Printed to
	// stderr: there is no logger yet, and stdout is the stdio JSON-RPC stream.
	if len(cfg.InvalidSettings) > 0 {
		for _, s := range cfg.InvalidSettings {
			fmt.Fprintf(os.Stderr, "config: %s\n", s)
		}
		fmt.Fprintln(os.Stderr, "config: refusing to start with an unparseable setting; fix it or unset it")
		os.Exit(1)
	}
	if *stdio {
		runStdio(cfg)
		return
	}
	runHTTP(cfg)
}

// runStdio serves a single tenant over stdio, for local MCP hosts like Claude
// Desktop. Credentials come from the environment (no per-request headers exist
// on stdio). All logging goes to stderr so it never corrupts the JSON-RPC stream.
func runStdio(cfg config.Config) {
	ident := armo.Identity{
		CustomerGUID: os.Getenv("ARMO_CUSTOMER_GUID"),
		APIKey:       os.Getenv("ARMO_ACCESS_KEY"),
	}
	if ident.CustomerGUID == "" || ident.APIKey == "" {
		log.Fatal("stdio mode requires ARMO_CUSTOMER_GUID and ARMO_ACCESS_KEY environment variables")
	}
	toolServer := &tools.Server{
		Client: armo.New(cfg.APIBaseURL, nil),
		Auth:   auth.StaticAuthenticator{ID: ident},
		Cfg:    cfg,
	}
	m := mcp.NewServer(&mcp.Implementation{Name: "armo-mcp", Version: version}, nil)
	toolServer.Register(m)
	log.Printf("armo-mcp %s starting on stdio (backend %s)", version, cfg.APIBaseURL)
	if err := m.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

// runHTTP serves the multi-tenant Streamable HTTP transport; each request's
// identity is resolved from its own auth headers.
func runHTTP(cfg config.Config) {
	ctx := context.Background()

	logger := telemetry.InitLogger(cfg.ServiceName, cfg.Environment, "info")
	defer func() { _ = logger.Sync() }()

	shutdownTracer, err := telemetry.InitTracer(ctx, cfg.ServiceName, cfg.Environment, cfg.JaegerAgentHost, cfg.JaegerAgentPort)
	if err != nil {
		logger.Error("failed to init tracer, continuing without tracing", zap.Error(err))
		shutdownTracer = func(context.Context) error { return nil }
	}
	defer func() { _ = shutdownTracer(context.Background()) }()

	m := metrics.New()

	toolServer := &tools.Server{
		Client:  armo.New(cfg.APIBaseURL, nil),
		Auth:    auth.APIKeyAuthenticator{},
		Cfg:     cfg,
		Limiter: limit.New(cfg.RateLimitPerMin, cfg.RateLimitBurst),
		Cache:   cache.New[tools.QueryResult](cfg.CacheTTL),
		Metrics: m,
		// Names change rarely; a token lasts an hour at most.
		Accounts: cache.New[[]armo.Account](5 * time.Minute),
	}

	getServer := func(r *http.Request) *mcp.Server {
		srv := mcp.NewServer(&mcp.Implementation{Name: "armo-mcp", Version: version}, nil)
		toolServer.Register(srv)
		return srv
	}
	mcpHandler := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{Stateless: true})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	if cfg.OAuthEnabled {
		// Every failure below stops the process; half-configured never means open.
		if err := auth.ValidateResourceURL(cfg.MCPResourceURL); err != nil {
			logger.Fatal("OAuth is enabled but the MCP resource URL is invalid", zap.Error(err))
		}
		oauthAuth, err := auth.NewOAuthAuthenticator(ctx, cfg.OAuthIssuer, cfg.OAuthClientID)
		if err != nil {
			logger.Fatal("OAuth is enabled but the authenticator could not be built", zap.Error(err))
		}
		toolServer.Auth = oauthAuth
		if err := auth.Mount(mux, oauthAuth, cfg.MCPResourceURL, cfg.OAuthIssuer, mcpHandler); err != nil {
			logger.Fatal("could not register the OAuth routes", zap.Error(err))
		}
	} else {
		mux.Handle("/mcp", mcpHandler)
	}

	handler := otelhttp.NewHandler(m.HTTPMiddleware(limitBody(mux)), "mcp")

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Separate metrics server, so /metrics is never reachable through the
	// main mux (and never subject to its rate limiting/tracing wrapping).
	mux2 := http.NewServeMux()
	mux2.Handle("/metrics", m.Handler())
	metricsSrv := &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           mux2,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", zap.Error(err))
		}
	}()

	log.Printf("armo-mcp %s listening on %s (backend %s, metrics on %s)", version, cfg.ListenAddr, cfg.APIBaseURL, cfg.MetricsAddr)

	srvErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			srvErr <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Block until either a shutdown signal or a fatal serve error. Routing the
	// error through a channel (instead of log.Fatal inside the goroutine) means
	// a failed ListenAndServe still unwinds through the graceful-shutdown path
	// below and runs the deferred tracer/logger flushes, rather than exiting
	// immediately and skipping them.
	select {
	case err := <-srvErr:
		logger.Error("http server error, shutting down", zap.Error(err))
	case s := <-sig:
		log.Printf("armo-mcp %s received signal %s, shutting down", version, s)
	}

	ctx2, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx2); err != nil {
		logger.Error("error during graceful shutdown", zap.Error(err))
	}
	_ = metricsSrv.Shutdown(ctx2)
}

// maxRequestBody bounds what a single request may make the server buffer. MCP
// requests are small JSON-RPC messages; a megabyte leaves ample room.
const maxRequestBody = 1 << 20

// limitBody refuses a request whose declared length is over the limit, and caps
// what can be read from one that declares none (chunked) at the same size.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxRequestBody {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next.ServeHTTP(w, r)
	})
}
