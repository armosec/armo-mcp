package tools

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/auth"
	"github.com/armosec/armo-mcp/internal/cache"
	"github.com/armosec/armo-mcp/internal/limit"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestCallCachesIdenticalRequests exercises the run -> cache-hit path of the
// call funnel: identical (tenant, tool, input) tuples must not re-invoke run.
// The limiter is generous (burst well above the two Allow() calls this test
// makes) so it never interferes with this assertion; rate-limit behavior is
// covered separately in TestCallRateLimits.
func TestCallCachesIdenticalRequests(t *testing.T) {
	s := &Server{
		Auth:    auth.StaticAuthenticator{ID: armo.Identity{CustomerGUID: "t1", APIKey: "k"}},
		Limiter: limit.New(60, 5),
		Cache:   cache.New[QueryResult](time.Minute),
	}
	req := &mcp.CallToolRequest{}

	runs := 0
	run := func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		runs++
		return QueryResult{Total: 1, Count: 1, Items: []map[string]any{{"n": runs}}}, nil
	}
	in := map[string]any{"severity": "Critical", "page": 1}

	// (a) first call: runs, returns the result.
	_, out1, err := s.call(context.Background(), req, "query_vulnerabilities", in, run)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if runs != 1 {
		t.Fatalf("runs = %d, want 1 after first call", runs)
	}
	if out1.Total != 1 || len(out1.Items) != 1 {
		t.Fatalf("out1 = %+v", out1)
	}

	// (b) second identical call: cache hit, run counter unchanged.
	_, out2, err := s.call(context.Background(), req, "query_vulnerabilities", in, run)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if runs != 1 {
		t.Fatalf("runs = %d after second identical call, want 1 (expected cache hit)", runs)
	}
	if out2.Items[0]["n"] != out1.Items[0]["n"] {
		t.Fatalf("cached result mismatch: out1=%+v out2=%+v", out1, out2)
	}

	// A different input is a different cache key: run must fire again.
	_, out3, err := s.call(context.Background(), req, "query_vulnerabilities", map[string]any{"severity": "Low"}, run)
	if err != nil {
		t.Fatalf("third call: %v", err)
	}
	if runs != 2 {
		t.Fatalf("runs = %d after differing-input call, want 2", runs)
	}
	if out3.Items[0]["n"] == out1.Items[0]["n"] {
		t.Fatalf("expected a fresh run for a different cache key")
	}
}

// TestCallRateLimits exercises the rate-limit short-circuit: once the
// per-tenant token bucket (burst 1) is exhausted, further calls fail with a
// "rate limit" error even when they target a distinct cache key (i.e. the
// limiter is consulted before the cache, so a fresh key does not bypass it).
func TestCallRateLimits(t *testing.T) {
	s := &Server{
		Auth:    auth.StaticAuthenticator{ID: armo.Identity{CustomerGUID: "t1", APIKey: "k"}},
		Limiter: limit.New(60, 1), // burst 1: exactly one call gets through immediately
		Cache:   cache.New[QueryResult](time.Minute),
	}
	req := &mcp.CallToolRequest{}
	run := func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		return QueryResult{Total: 1}, nil
	}

	// Consume the single burst token.
	if _, _, err := s.call(context.Background(), req, "query_vulnerabilities", map[string]any{"a": 1}, run); err != nil {
		t.Fatalf("first call should pass: %v", err)
	}

	// Beyond the burst, even with a brand-new cache key, must be rejected.
	_, _, err := s.call(context.Background(), req, "query_vulnerabilities", map[string]any{"a": 2}, run)
	if err == nil {
		t.Fatal("expected rate-limit error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "rate limit") {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), "rate limit")
	}
}

// TestCallResolveIdentityError verifies the wrapper surfaces auth failures
// before touching the limiter/cache, and that a nil Limiter/Cache/Metrics
// (the stdio / unit-test default) does not panic.
func TestCallResolveIdentityError(t *testing.T) {
	s := &Server{Auth: auth.StaticAuthenticator{}} // no ID configured -> Resolve errors
	req := &mcp.CallToolRequest{}
	called := false
	run := func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		called = true
		return QueryResult{}, nil
	}

	if _, _, err := s.call(context.Background(), req, "query_vulnerabilities", map[string]any{}, run); err == nil {
		t.Fatal("expected an identity-resolution error")
	}
	if called {
		t.Fatal("run must not be invoked when identity resolution fails")
	}
}

// TestCacheKeyIsPerCredential is the unit-level guard for the cross-credential
// cache leak: within one tenant, two different access keys making the same
// (tool, input) call must map to DIFFERENT cache keys, the same key must be
// stable, and the access key must never appear in cleartext.
func TestCacheKeyIsPerCredential(t *testing.T) {
	in := map[string]any{"severity": "Critical", "page": 1}

	kA := cacheKey(armo.Identity{CustomerGUID: "t1", APIKey: "key-A"}, "query_vulnerabilities", in)
	kB := cacheKey(armo.Identity{CustomerGUID: "t1", APIKey: "key-B"}, "query_vulnerabilities", in)
	if kA == "" || kB == "" {
		t.Fatal("cache keys should be non-empty for marshalable input")
	}
	if kA == kB {
		t.Fatal("SECURITY: different credentials in the same tenant produced the same cache key")
	}
	if kA != cacheKey(armo.Identity{CustomerGUID: "t1", APIKey: "key-A"}, "query_vulnerabilities", in) {
		t.Fatal("same credential + input must yield a stable cache key (else cache never hits)")
	}
	if strings.Contains(kA, "key-A") {
		t.Fatal("SECURITY: access key appears in the cache key in cleartext")
	}
}

// TestCallDoesNotServeAcrossCredentials is the funnel-level guard: a caller who
// knows only the (non-secret) tenant GUID but presents a bogus/revoked access
// key must NOT be served another credential's cached result. run() must fire so
// the bad key reaches cadashboardbe (which rejects it) instead of being
// short-circuited by a cache hit.
func TestCallDoesNotServeAcrossCredentials(t *testing.T) {
	shared := cache.New[QueryResult](time.Minute)
	mkServer := func(key string) *Server {
		return &Server{
			Auth:    auth.StaticAuthenticator{ID: armo.Identity{CustomerGUID: "t1", APIKey: key}},
			Limiter: limit.New(6000, 100),
			Cache:   shared,
		}
	}
	req := &mcp.CallToolRequest{}
	in := map[string]any{"severity": "Critical"}

	// Legitimate user populates the cache for this tenant+tool+input.
	legit := mkServer("real-key")
	if _, _, err := legit.call(context.Background(), req, "query_vulnerabilities", in,
		func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
			return QueryResult{Total: 1, Items: []map[string]any{{"secret": "tenant-data"}}}, nil
		}); err != nil {
		t.Fatalf("legit call: %v", err)
	}

	// Attacker: same GUID, bogus key, same query. Must miss the cache and hit run().
	attacker := mkServer("bogus-key")
	attackerRan := false
	_, _, _ = attacker.call(context.Background(), req, "query_vulnerabilities", in,
		func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
			attackerRan = true
			return QueryResult{}, errors.New("unauthorized: backend returned 401")
		})
	if !attackerRan {
		t.Fatal("SECURITY: a caller with a different credential was served the tenant's cached data")
	}
}

// TestCacheKeyAPIKeyLayoutIsFrozen pins the exact key an API-key identity
// produced before OAuth support existed (captured from the pre-change code).
// Changing it silently orphans every live cache entry, and stdio mode rides on
// the same layout, so this must only ever change deliberately.
func TestCacheKeyAPIKeyLayoutIsFrozen(t *testing.T) {
	in := map[string]any{"severity": "Critical", "page": 1}
	const wantKeyA = "t1|b7930bd94b2ed34db59ce807de370ffa8b97fd736030a5c28fed9f6fcdccd271|query_vulnerabilities|29565d269eb81e6dfafd86ac427cb2ca310cb091e85ae0cf0b2aff6e377f1826"
	if got := cacheKey(armo.Identity{CustomerGUID: "t1", APIKey: "key-A"}, "query_vulnerabilities", in); got != wantKeyA {
		t.Fatalf("API-key cache key changed:\n got %s\nwant %s", got, wantKeyA)
	}
	const wantEmpty = "t1|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|query_vulnerabilities|29565d269eb81e6dfafd86ac427cb2ca310cb091e85ae0cf0b2aff6e377f1826"
	if got := cacheKey(armo.Identity{CustomerGUID: "t1"}, "query_vulnerabilities", in); got != wantEmpty {
		t.Fatalf("empty-credential cache key changed:\n got %s\nwant %s", got, wantEmpty)
	}
}

// TestCacheKeyIsPerOAuthUser guards the OAuth path, where APIKey is always
// empty: two users in one tenant must not share a cache namespace.
func TestCacheKeyIsPerOAuthUser(t *testing.T) {
	in := map[string]any{"severity": "Critical"}
	alice := armo.Identity{CustomerGUID: "t1", Bearer: "token-alice"}
	bob := armo.Identity{CustomerGUID: "t1", Bearer: "token-bob"}

	kA := cacheKey(alice, "query_vulnerabilities", in)
	kB := cacheKey(bob, "query_vulnerabilities", in)
	if kA == "" || kB == "" {
		t.Fatal("cache keys should be non-empty for marshalable input")
	}
	if kA == kB {
		t.Fatal("SECURITY: two OAuth users in the same tenant produced the same cache key")
	}
	if kA != cacheKey(alice, "query_vulnerabilities", in) {
		t.Fatal("same OAuth identity + input must yield a stable cache key (else cache never hits)")
	}
	if strings.Contains(kA, "token-alice") {
		t.Fatal("SECURITY: bearer token appears in the cache key in cleartext")
	}
	// A bearer token must never collapse onto the key of an API-key identity,
	// even if the strings are equal, nor onto the empty-credential key.
	if kA == cacheKey(armo.Identity{CustomerGUID: "t1", APIKey: "token-alice"}, "query_vulnerabilities", in) {
		t.Fatal("SECURITY: OAuth and API-key identities share a cache key")
	}
	if kA == cacheKey(armo.Identity{CustomerGUID: "t1"}, "query_vulnerabilities", in) {
		t.Fatal("SECURITY: OAuth identity shares the empty-credential cache namespace")
	}
}

// fixedAuth returns a fixed identity as-is. StaticAuthenticator is unusable for
// OAuth-shaped identities because it requires an API key.
type fixedAuth struct{ id armo.Identity }

func (f fixedAuth) Resolve(http.Header) (armo.Identity, error) { return f.id, nil }

// TestCallDoesNotServeAcrossOAuthUsers is the funnel-level guard: user B, in
// the same tenant as user A, must not be served A's cached result.
func TestCallDoesNotServeAcrossOAuthUsers(t *testing.T) {
	shared := cache.New[QueryResult](time.Minute)
	mkServer := func(token string) *Server {
		return &Server{
			Auth:    fixedAuth{armo.Identity{CustomerGUID: "t1", Bearer: token}},
			Limiter: limit.New(6000, 100),
			Cache:   shared,
		}
	}
	req := &mcp.CallToolRequest{}
	in := map[string]any{"severity": "Critical"}

	if _, _, err := mkServer("token-broad").call(context.Background(), req, "query_vulnerabilities", in,
		func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
			return QueryResult{Total: 1, Items: []map[string]any{{"secret": "broad-role-data"}}}, nil
		}); err != nil {
		t.Fatalf("first user: %v", err)
	}

	ran := false
	if _, _, err := mkServer("token-narrow").call(context.Background(), req, "query_vulnerabilities", in,
		func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
			ran = true
			return QueryResult{}, nil
		}); err != nil {
		t.Fatalf("second user: %v", err)
	}
	if !ran {
		t.Fatal("SECURITY: an OAuth user was served another user's cached result")
	}
}

// A cache hit returns before run(), so the backend never sees the request —
// and the backend is where logout invalidation and authorization
// live. Caching a bearer identity would let a revoked token keep
// reading for up to the cache TTL.
func TestBearerIdentitiesAreNotCached(t *testing.T) {
	s := &Server{
		Auth:    fixedAuth{id: armo.Identity{CustomerGUID: "t1", Bearer: "tok-alice"}},
		Limiter: limit.New(60, 10),
		Cache:   cache.New[QueryResult](time.Minute),
	}
	req := &mcp.CallToolRequest{}
	in := map[string]any{"severity": "Critical", "page": 1}

	runs := 0
	run := func(context.Context, armo.Identity) (QueryResult, error) {
		runs++
		return QueryResult{Total: 1, Count: 1}, nil
	}

	for i := 0; i < 3; i++ {
		if _, _, err := s.call(context.Background(), req, "query_vulnerabilities", in, run); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if runs != 3 {
		t.Errorf("run() was invoked %d times for 3 identical bearer calls, want 3; a cached hit "+
			"skips the backend's revocation and policy checks", runs)
	}
}

// The API-key path keeps caching, unchanged.
func TestAPIKeyIdentitiesStillCache(t *testing.T) {
	s := &Server{
		Auth:    auth.StaticAuthenticator{ID: armo.Identity{CustomerGUID: "t1", APIKey: "k"}},
		Limiter: limit.New(60, 10),
		Cache:   cache.New[QueryResult](time.Minute),
	}
	req := &mcp.CallToolRequest{}
	in := map[string]any{"severity": "Critical", "page": 1}

	runs := 0
	run := func(context.Context, armo.Identity) (QueryResult, error) {
		runs++
		return QueryResult{Total: 1, Count: 1}, nil
	}

	for i := 0; i < 3; i++ {
		if _, _, err := s.call(context.Background(), req, "query_vulnerabilities", in, run); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if runs != 1 {
		t.Errorf("run() was invoked %d times, want 1: the API-key path must still cache", runs)
	}
}

// In API-key mode the GUID is the caller's claim, not yet checked by the
// backend. A caller holding the GUID but not the key must not be able to
// drain the real key holder's rate limit.
func TestCallRateLimitIsNotKeyedOnUnverifiedGUID(t *testing.T) {
	lim := limit.New(60, 1)
	run := func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		return QueryResult{Total: 1}, nil
	}
	attacker := &Server{
		Auth:    auth.StaticAuthenticator{ID: armo.Identity{CustomerGUID: "victim", APIKey: "garbage"}},
		Limiter: lim,
	}
	victim := &Server{
		Auth:    auth.StaticAuthenticator{ID: armo.Identity{CustomerGUID: "victim", APIKey: "real-key"}},
		Limiter: lim,
	}
	req := &mcp.CallToolRequest{}
	for i := 0; i < 3; i++ {
		_, _, _ = attacker.call(context.Background(), req, "query_vulnerabilities", map[string]any{"i": i}, run)
	}
	if _, _, err := victim.call(context.Background(), req, "query_vulnerabilities", map[string]any{"v": 1}, run); err != nil {
		t.Fatalf("victim was rate limited by a caller without its key: %v", err)
	}
}
