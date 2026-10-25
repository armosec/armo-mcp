package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// call is the single funnel every tool handler goes through: resolve the
// caller's identity, select the account the input names, enforce the
// per-tenant rate limit, serve from cache when possible, otherwise run the
// pure tool method — recording an audit-log line and Prometheus metrics for
// every path.
//
// Limiter, Cache and Metrics on Server are all nil-able: when a dependency is
// unset (disabled by config, or simply absent in a unit test / stdio mode)
// its stage is skipped entirely rather than panicking.
//
// The access key and raw tool input are never written to logs — only the
// tenant GUID, tool name, timing and outcome.
func (s *Server) call(
	ctx context.Context,
	req *mcp.CallToolRequest,
	tool string,
	in any,
	run func(context.Context, armo.Identity) (QueryResult, error),
) (*mcp.CallToolResult, QueryResult, error) {
	traceID := trace.SpanContextFromContext(ctx).TraceID().String()

	ident, err := s.resolveIdentity(req)
	if err != nil {
		// Auth failed before a tenant could be established. Record the outcome
		// (no tenant to attribute, and never the offending header) so this path
		// is observable like every other.
		if s.Metrics != nil {
			s.Metrics.ToolCall(tool, "auth_error")
		}
		zap.L().Warn("tool call rejected: authentication failed",
			zap.String("tool", tool),
			zap.String("trace_id", traceID),
		)
		return nil, QueryResult{}, err
	}

	var want string
	if sel, ok := in.(accountSelector); ok {
		want = sel.selectedAccount()
	}
	ident, account, err := s.selectAccount(ctx, ident, want)
	if err != nil {
		if s.Metrics != nil {
			s.Metrics.ToolCall(tool, "account_error")
		}
		// The reason only: the error quotes the caller's raw account input.
		zap.L().Warn("tool call rejected: account selection failed",
			zap.String("tool", tool),
			zap.String("trace_id", traceID),
			zap.String("reason", accountErrorReason(err)),
		)
		return nil, QueryResult{}, err
	}

	if s.Limiter != nil && !s.Limiter.Allow(limitKey(ident)) {
		if s.Metrics != nil {
			s.Metrics.RateLimited()
		}
		zap.L().Warn("tool call rate limited",
			zap.String("tenant", ident.CustomerGUID),
			zap.String("tool", tool),
			zap.String("trace_id", traceID),
		)
		return nil, QueryResult{}, errors.New("rate limit exceeded: too many requests for this tenant, please retry shortly")
	}

	// Names are labels only: look them up once the call has passed the limiter,
	// alongside the data request rather than before it.
	nameCh := make(chan string, 1)
	go func() { nameCh <- s.accountName(ctx, ident, account.GUID) }()

	// Only derive the key when caching is enabled — marshaling the input is
	// wasted work in stdio/unit-test mode where Cache is nil.
	// Bearer identities are never cached: a hit returns before run(), skipping
	// the backend's logout and policy checks.
	var key string
	if s.Cache != nil && ident.Bearer == "" {
		key = cacheKey(ident, tool, in)
	}

	if s.Cache != nil && key != "" {
		if cached, ok := s.Cache.Get(key); ok {
			if s.Metrics != nil {
				s.Metrics.CacheEvent("hit")
				s.Metrics.ToolCall(tool, "ok")
			}
			zap.L().Info("tool call audit",
				zap.String("tenant", ident.CustomerGUID),
				zap.String("tool", tool),
				zap.Int64("latency_ms", 0),
				zap.String("result", "ok"),
				zap.String("trace_id", traceID),
				zap.Bool("cached", true),
			)
			return nil, cached, nil
		}
		// Cache enabled but the key wasn't present: this call will hit run().
		if s.Metrics != nil {
			s.Metrics.CacheEvent("miss")
		}
	}

	start := time.Now()
	out, runErr := run(ctx, ident)
	latencyMS := time.Since(start).Milliseconds()

	result := "ok"
	if runErr != nil {
		result = "error"
	}
	logger := zap.L()
	fields := []zap.Field{
		zap.String("tenant", ident.CustomerGUID),
		zap.String("tool", tool),
		zap.Int64("latency_ms", latencyMS),
		zap.String("result", result),
		zap.String("trace_id", traceID),
		zap.Bool("cached", false),
	}
	if runErr != nil {
		logger.Error("tool call audit", append(fields, zap.Error(runErr))...)
	} else {
		logger.Info("tool call audit", fields...)
	}

	if s.Metrics != nil {
		s.Metrics.ToolCall(tool, result)

		backendResult := "ok"
		if runErr != nil {
			if errors.Is(runErr, armo.ErrBackendUnavailable) {
				backendResult = "open"
			} else {
				backendResult = "error"
			}
		}
		s.Metrics.BackendRequest(backendResult)
	}

	if runErr != nil {
		return nil, QueryResult{}, runErr
	}
	account.Name = <-nameCh
	out.Account = &account

	if s.Cache != nil && key != "" {
		s.Cache.Set(key, out)
		if s.Metrics != nil {
			s.Metrics.CacheEvent("store")
		}
	}

	return nil, out, nil
}

// cacheKey derives a per-credential, per-tenant, per-tool, per-input cache key.
//
// An entry is served back only to the exact credential that fetched it: the
// key hashes the API key (the pre-OAuth layout) or, under a "bearer:" prefix,
// the raw bearer token. call never caches bearers today; the branch keeps the
// key per-user if that changes.
//
// Hashing the marshaled input (rather than embedding it directly) keeps keys
// short and keeps raw request parameters out of anything that might log or
// persist the key. If the input can't be marshaled, caching is disabled for
// this call by returning an empty key.
func cacheKey(ident armo.Identity, tool string, in any) string {
	b, err := json.Marshal(in)
	if err != nil {
		return ""
	}
	var cred string
	if ident.Bearer != "" {
		h := sha256.Sum256([]byte(ident.Bearer + "\x00" + ident.APIKey))
		cred = "bearer:" + hex.EncodeToString(h[:])
	} else {
		h := sha256.Sum256([]byte(ident.APIKey))
		cred = hex.EncodeToString(h[:])
	}
	sum := sha256.Sum256(b)
	return ident.CustomerGUID + "|" + cred + "|" + tool + "|" + hex.EncodeToString(sum[:])
}

// limitKey is the rate-limit bucket for an identity. A bearer token has been
// verified by the time it gets here, so its tenant is the key. An API key has
// not: the backend checks it later, so the GUID alone is only the caller's
// claim. Folding a hash of the key in means a caller without the key cannot
// spend the key holder's budget.
func limitKey(ident armo.Identity) string {
	if ident.Bearer != "" {
		return ident.CustomerGUID
	}
	sum := sha256.Sum256([]byte(ident.APIKey))
	return ident.CustomerGUID + ":" + hex.EncodeToString(sum[:8])
}
