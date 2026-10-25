package auth

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestStaticAuthenticator(t *testing.T) {
	id := armo.Identity{CustomerGUID: "g", APIKey: "k"}
	// nil header simulates stdio transport (no HTTP headers).
	got, err := (StaticAuthenticator{ID: id}).Resolve(nil)
	if err != nil || !reflect.DeepEqual(got, id) {
		t.Fatalf("Resolve(nil) = %+v, %v; want %+v, nil", got, err, id)
	}
	if _, err := (StaticAuthenticator{}).Resolve(nil); err == nil {
		t.Error("empty StaticAuthenticator should return an error")
	}
}

func TestAPIKeyResolveOK(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer secret-key")
	h.Set("X-Armo-Customer-Guid", "cust-123")
	id, err := APIKeyAuthenticator{}.Resolve(h)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if id.APIKey != "secret-key" || id.CustomerGUID != "cust-123" {
		t.Errorf("identity = %+v, want key secret-key / guid cust-123", id)
	}
}

func TestAPIKeyResolvePacked(t *testing.T) {
	// Single-credential form for hosts that only allow one field (e.g. ChatGPT):
	// Authorization: Bearer <customerGUID>:<accessKey>, no X-Armo-Customer-Guid header.
	// Split on the FIRST colon (GUID and access key are UUIDs, no internal colons).
	guid := "00000000-0000-4000-8000-000000000001"
	key := "00000000-0000-4000-8000-0000000000ff"
	h := http.Header{}
	h.Set("Authorization", "Bearer "+guid+":"+key)
	id, err := APIKeyAuthenticator{}.Resolve(h)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if id.CustomerGUID != guid || id.APIKey != key {
		t.Errorf("identity = %+v, want guid %s / key %s", id, guid, key)
	}
}

func TestAPIKeyResolveHeaderTakesPrecedence(t *testing.T) {
	// When the explicit X-Armo-Customer-Guid header is present it wins, and the bearer
	// token is the access key verbatim (no packed split) — the two-header form is unchanged.
	h := http.Header{}
	h.Set("Authorization", "Bearer a:b")
	h.Set("X-Armo-Customer-Guid", "cust-123")
	id, err := APIKeyAuthenticator{}.Resolve(h)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if id.CustomerGUID != "cust-123" || id.APIKey != "a:b" {
		t.Errorf("identity = %+v, want guid cust-123 / key a:b", id)
	}
}

func TestAPIKeyResolveMissing(t *testing.T) {
	cases := []http.Header{
		{},
		{"Authorization": {"Bearer k"}}, // no guid
		{"X-Armo-Customer-Guid": {"g"}}, // no key
		{"Authorization": {"Basic k"}, "X-Armo-Customer-Guid": {"g"}}, // wrong scheme
	}
	for i, h := range cases {
		if _, err := (APIKeyAuthenticator{}).Resolve(h); err == nil || !strings.HasPrefix(err.Error(), "unauthenticated") {
			t.Errorf("case %d: err = %v, want prefix 'unauthenticated'", i, err)
		}
	}
}
