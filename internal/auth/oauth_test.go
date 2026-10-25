package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// newTestIDP starts a throwaway OpenID provider: an RSA key, a discovery
// document and a JWKS endpoint. Returns the issuer URL and a mint function.
// go-jose v4 comes in with go-oidc, so no new dependency.
func newTestIDP(t *testing.T) (issuer string, mint func(map[string]any) string) {
	t.Helper()
	issuer, mint, _ = newCountingTestIDP(t)
	return issuer, mint
}

// newCountingTestIDP is newTestIDP that also counts JWKS requests.
func newCountingTestIDP(t *testing.T) (issuer string, mint func(map[string]any) string, jwksHits *atomic.Int64) {
	t.Helper()
	jwksHits = &atomic.Int64{}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "test-key"

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"jwks_uri":                              srv.URL + "/.well-known/jwks.json",
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		jwksHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key.Public(), KeyID: kid, Algorithm: "RS256", Use: "sig",
		}}})
	})

	mint = signWith(t, key, kid, srv.URL)
	return srv.URL, mint, jwksHits
}

// signWith returns a mint function that signs claims with the given RSA key.
// iss defaults to defaultIss and can be overridden through the claims map.
func signWith(t *testing.T, key *rsa.PrivateKey, kid, defaultIss string) func(map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return func(claims map[string]any) string {
		c := map[string]any{"iss": defaultIss}
		for k, v := range claims {
			c[k] = v
		}
		payload, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal claims: %v", err)
		}
		obj, err := signer.Sign(payload)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		raw, err := obj.CompactSerialize()
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}
		return raw
	}
}

func validClaims() map[string]any {
	return map[string]any{
		"aud": []string{"mcp-client"}, "sub": "u1",
		"tenantId": "tenant-a", "roles": []string{"ReadOnly"},
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

func bearer(tok string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	return h
}

func TestOAuthResolveOK(t *testing.T) {
	issuer, mint := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	tok := mint(validClaims())

	id, err := a.Resolve(bearer(tok))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.CustomerGUID != "tenant-a" {
		t.Errorf("CustomerGUID = %q, want tenant-a", id.CustomerGUID)
	}
	if id.Bearer != tok {
		t.Error("Bearer must be the raw token, forwarded unchanged")
	}
	if id.APIKey != "" {
		t.Error("APIKey must stay empty on the OAuth path")
	}
}

// The tenant must come from the token. A client-supplied customer header (the
// API-key path's tenant selector) and an x-api-key header must have no effect.
func TestOAuthResolveIgnoresClientSuppliedTenantAndAPIKey(t *testing.T) {
	issuer, mint := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	h := bearer(mint(validClaims()))
	h.Set("X-Armo-Customer-Guid", "tenant-victim")
	h.Set("X-Api-Key", "attacker-key")

	id, err := a.Resolve(h)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.CustomerGUID != "tenant-a" {
		t.Errorf("CustomerGUID = %q, want tenant-a (from the token, not the header)", id.CustomerGUID)
	}
	if id.APIKey != "" {
		t.Errorf("APIKey = %q, want empty", id.APIKey)
	}
}

// RFC 6750: the scheme is case-insensitive, the credential is not.
func TestOAuthResolveSchemeCaseInsensitive(t *testing.T) {
	issuer, mint := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	tok := mint(validClaims())
	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		t.Run(scheme, func(t *testing.T) {
			h := http.Header{}
			h.Set("Authorization", scheme+" "+tok)
			id, err := a.Resolve(h)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if id.CustomerGUID != "tenant-a" {
				t.Errorf("CustomerGUID = %q, want tenant-a", id.CustomerGUID)
			}
			if id.Bearer != tok {
				t.Error("Bearer must be the token bytes exactly as sent")
			}
		})
	}

	// Case-folding must stop at the scheme: an upper-cased credential is a
	// different (and invalid) token.
	h := http.Header{}
	h.Set("Authorization", "bearer "+strings.ToUpper(tok))
	if _, err := a.Resolve(h); err == nil {
		t.Error("an upper-cased token must not validate")
	}
}

func TestOAuthResolveRejects(t *testing.T) {
	issuer, mint := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong audience", func(c map[string]any) { c["aud"] = []string{"other"} }},
		{"missing audience", func(c map[string]any) { delete(c, "aud") }},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example.com" }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"no tenantId", func(c map[string]any) { delete(c, "tenantId") }},
		{"empty tenantId", func(c map[string]any) { c["tenantId"] = "" }},
		// tenantIds is the list of tenants the user belongs to; it must never
		// stand in for the active tenant.
		{"tenantIds only", func(c map[string]any) {
			delete(c, "tenantId")
			c["tenantIds"] = []string{"tenant-a", "tenant-b"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims()
			tc.mutate(claims)
			_, err := a.Resolve(bearer(mint(claims)))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.HasPrefix(err.Error(), "unauthenticated") {
				t.Errorf("err = %v, want prefix 'unauthenticated'", err)
			}
		})
	}
}

// A token with valid claims signed by a key the issuer does not publish must
// be rejected, even if it carries the right kid.
func TestOAuthResolveRejectsForeignSignature(t *testing.T) {
	issuer, _ := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	forged := signWith(t, attackerKey, "test-key", issuer)(validClaims())
	if _, err := a.Resolve(bearer(forged)); err == nil {
		t.Fatal("token signed by an unpublished key must be rejected")
	}
}

func TestOAuthResolveMissingOrMalformed(t *testing.T) {
	issuer, _ := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	for _, h := range []http.Header{
		nil,
		{},
		{"Authorization": {"Basic abc"}},
		{"Authorization": {"Bearer "}},
		{"Authorization": {"Bearer not.a.jwt"}},
	} {
		if _, err := a.Resolve(h); err == nil || !strings.HasPrefix(err.Error(), "unauthenticated") {
			t.Errorf("header %v: err = %v, want prefix 'unauthenticated'", h, err)
		}
	}
}

func TestNewOAuthAuthenticatorRejectsEmptyClientID(t *testing.T) {
	issuer, _ := newTestIDP(t)
	if _, err := NewOAuthAuthenticator(context.Background(), issuer, ""); err == nil {
		t.Fatal("an empty client ID would disable the audience check and must be refused")
	}
}

// There is no default issuer: an empty one must be refused by name before any
// discovery request, not surface as a confusing "Get /.well-known/..." error.
func TestNewOAuthAuthenticatorRejectsEmptyIssuer(t *testing.T) {
	_, err := NewOAuthAuthenticator(context.Background(), "", "mcp-client")
	if err == nil || !strings.Contains(err.Error(), "ARMO_OAUTH_ISSUER") {
		t.Fatalf("err = %v, want one naming ARMO_OAUTH_ISSUER", err)
	}
}

// Discovery and JWKS decide which keys are trusted, so a remote issuer over
// plaintext is refused before any request is made. Loopback is exempt.
func TestNewOAuthAuthenticatorRequiresHTTPSForRemoteIssuer(t *testing.T) {
	for _, issuer := range []string{"http://idp.example.com/"} {
		_, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
		if err == nil || !strings.Contains(err.Error(), "must use https") {
			t.Errorf("issuer %q: err = %v, want the https refusal", issuer, err)
		}
	}
	for _, issuer := range []string{"http://127.0.0.1:1", "http://localhost:1", "http://[::1]:1"} {
		_, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
		if err != nil && strings.Contains(err.Error(), "must use https") {
			t.Errorf("loopback issuer %q must be allowed over http: %v", issuer, err)
		}
	}
}

// Construction must not hang when the IdP is unreachable.
func TestNewOAuthAuthenticatorFailsFastOnUnreachableIssuer(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		_, err := NewOAuthAuthenticator(context.Background(), "https://127.0.0.1:1/nowhere", "mcp-client")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for an unreachable issuer")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("construction hung; the discovery client needs a timeout")
	}
}

// A refused connection returns at once whether or not a timeout is set, so the
// test above cannot prove one exists. This one points discovery at a server
// that accepts the request and never answers.
func TestNewOAuthAuthenticatorTimesOutOnUnresponsiveIssuer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs before srv.Close, unblocking handlers

	old := discoveryTimeout
	discoveryTimeout = 200 * time.Millisecond
	t.Cleanup(func() { discoveryTimeout = old })

	done := make(chan error, 1)
	go func() {
		_, err := NewOAuthAuthenticator(context.Background(), srv.URL, "mcp-client")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for an unresponsive issuer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("construction hung on an unresponsive issuer; the discovery client has no effective timeout")
	}
}

// tenantIds lists the other accounts a request may name; the active tenant
// still comes only from tenantId.
func TestOAuthResolveCarriesTenantIDs(t *testing.T) {
	issuer, mint := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	c := validClaims()
	c["tenantIds"] = []string{"tenant-a", "tenant-b"}
	id, err := a.Resolve(bearer(mint(c)))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.CustomerGUID != "tenant-a" {
		t.Errorf("CustomerGUID = %q, want tenant-a", id.CustomerGUID)
	}
	if len(id.Tenants) != 2 || id.Tenants[1] != "tenant-b" {
		t.Errorf("Tenants = %v, want [tenant-a tenant-b]", id.Tenants)
	}
}
