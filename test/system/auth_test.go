//go:build systemtest

package system

import (
	"strings"
	"testing"
)

// TestAuthTwoHeaderWorks: the standard two-header form returns data.
func TestAuthTwoHeaderWorks(t *testing.T) {
	cfg := loadConfig(t)
	s := connect(t, cfg.Endpoint, twoHeaderRT(cfg.Key, cfg.GUID))
	res := callTool(t, s, "query_vulnerabilities", map[string]any{"page_size": 1})
	if res.IsError {
		t.Fatalf("two-header auth returned error: %+v", res.Content)
	}
}

// TestAuthPackedWorks: the packed "Bearer <guid>:<key>" single-credential form
// (used by ChatGPT) returns data, with no separate GUID header.
func TestAuthPackedWorks(t *testing.T) {
	cfg := loadConfig(t)
	s := connect(t, cfg.Endpoint, packedRT(cfg.GUID+":"+cfg.Key))
	res := callTool(t, s, "query_vulnerabilities", map[string]any{"page_size": 1})
	if res.IsError {
		t.Fatalf("packed auth returned error: %+v", res.Content)
	}
}

// TestAuthGarbageKeyRejected is the cross-credential regression lock: a valid
// (non-secret) GUID with a bogus key must NOT return data — even if a legit
// caller just cached the identical query. It must be rejected downstream (401).
func TestAuthGarbageKeyRejected(t *testing.T) {
	cfg := loadConfig(t)
	// Warm any cache with a legit identical call first.
	warm := connect(t, cfg.Endpoint, twoHeaderRT(cfg.Key, cfg.GUID))
	_ = callTool(t, warm, "query_vulnerabilities", map[string]any{"page_size": 1})

	s := connect(t, cfg.Endpoint, packedRT(cfg.GUID+":deadbeef-0000-0000-0000-000000000000"))
	res := callTool(t, s, "query_vulnerabilities", map[string]any{"page_size": 1})
	if !res.IsError {
		t.Fatalf("SECURITY: garbage key was served a result (cross-credential leak): %+v", res.StructuredContent)
	}
	text := contentText(res)
	if !strings.Contains(strings.ToLower(text), "unauthor") && !strings.Contains(text, "401") {
		t.Fatalf("garbage key rejected but not with an auth error; got: %q", text)
	}
	if res.StructuredContent != nil {
		t.Fatalf("garbage key returned structured data: %v", res.StructuredContent)
	}
}

// TestAuthMissingCredentialRejected: no Authorization header → rejected, no data.
func TestAuthMissingCredentialRejected(t *testing.T) {
	cfg := loadConfig(t)
	s := connect(t, cfg.Endpoint, rawRT(map[string]string{}))
	res := callTool(t, s, "query_vulnerabilities", map[string]any{"page_size": 1})
	if !res.IsError {
		t.Fatalf("missing credential was served a result: %+v", res.StructuredContent)
	}
	if res.StructuredContent != nil {
		t.Fatalf("missing credential returned structured data: %v", res.StructuredContent)
	}
	text := contentText(res)
	if !strings.Contains(strings.ToLower(text), "unauth") {
		t.Fatalf("missing credential rejected but not with an auth error; got: %q", text)
	}
}
