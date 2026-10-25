package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestProtectedResourceMetadata(t *testing.T) {
	h := ProtectedResourceHandler("https://api.armosec.io/mcp", "https://auth.armosec.io")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ProtectedResourcePath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var got struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Resource != "https://api.armosec.io/mcp" {
		t.Errorf("resource = %q", got.Resource)
	}
	if len(got.AuthorizationServers) != 1 || got.AuthorizationServers[0] != "https://auth.armosec.io" {
		t.Errorf("authorization_servers = %v", got.AuthorizationServers)
	}
	if len(got.BearerMethodsSupported) != 1 || got.BearerMethodsSupported[0] != "header" {
		t.Errorf("bearer_methods_supported = %v", got.BearerMethodsSupported)
	}
}

// Clients build `scope` from this document; an absent scopes_supported means
// no scope is sent and the authorization server rejects the request.
func TestProtectedResourceMetadataAdvertisesScopes(t *testing.T) {
	h := ProtectedResourceHandler("https://api.armosec.io/mcp", "https://auth.armosec.io")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ProtectedResourcePath, nil))

	var raw struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw.ScopesSupported) == 0 {
		t.Fatalf("scopes_supported is absent or empty: %s", rec.Body.String())
	}
	// openid is what makes this an OIDC request at all; without it there is no
	// ID token and the bearer path has no subject to bind.
	if !slices.Contains(raw.ScopesSupported, "openid") {
		t.Errorf("scopes_supported = %v, must include openid", raw.ScopesSupported)
	}
}

// RFC 9728 wire names are fixed by the spec. Decoding into a typed struct would
// not notice a renamed field, so check the raw keys, and that
// authorization_servers is a JSON array.
func TestProtectedResourceMetadataWireNames(t *testing.T) {
	h := ProtectedResourceHandler("https://api.armosec.io/mcp", "https://auth.armosec.io")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ProtectedResourcePath, nil))

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"resource", "authorization_servers", "bearer_methods_supported", "scopes_supported"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing key %q in %s", key, rec.Body.String())
		}
	}
	// Exact count, so adding a field to the struct without deciding whether
	// clients should see it fails here rather than shipping silently.
	if len(raw) != 4 {
		t.Errorf("got %d keys, want exactly 4", len(raw))
	}
	if s := string(raw["authorization_servers"]); len(s) == 0 || s[0] != '[' {
		t.Errorf("authorization_servers = %s, want a JSON array", s)
	}
}

// The endpoint is how a client discovers the authorization server, so it
// must answer without a token.
func TestProtectedResourceMetadataNeedsNoAuth(t *testing.T) {
	h := ProtectedResourceHandler("https://api.armosec.io/mcp", "https://auth.armosec.io")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ProtectedResourcePath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with no Authorization header", rec.Code)
	}
}
