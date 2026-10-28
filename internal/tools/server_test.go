package tools

import (
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestResolveIdentitySetsClientUA(t *testing.T) {
	s := &Server{Auth: auth.StaticAuthenticator{ID: armo.Identity{CustomerGUID: "g", APIKey: "k"}}}
	h := http.Header{}
	h.Set("User-Agent", "claude-code/2.0 (darwin)")

	ident, err := s.resolveIdentity(&mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: h}})
	if err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}
	if ident.ClientUA != "claude-code/2.0 (darwin)" {
		t.Errorf("ClientUA = %q, want %q", ident.ClientUA, "claude-code/2.0 (darwin)")
	}
}

// stdio requests carry no headers, so there is no User-Agent to forward.
func TestResolveIdentityWithoutHeaders(t *testing.T) {
	s := &Server{Auth: auth.StaticAuthenticator{ID: armo.Identity{CustomerGUID: "g", APIKey: "k"}}}
	ident, err := s.resolveIdentity(&mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}
	if ident.ClientUA != "" {
		t.Errorf("ClientUA = %q, want empty", ident.ClientUA)
	}
}
