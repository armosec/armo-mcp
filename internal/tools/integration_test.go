package tools

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/auth"
	"github.com/armosec/armo-mcp/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestEndToEndQueryVulnerabilities(t *testing.T) {
	// Fake cadashboardbe.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "key-1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, `{"response":[{"name":"CVE-9","severity":"Critical","cvssInfo":{"x":1}}],"total":{"value":1}}`)
	}))
	defer backend.Close()

	toolServer := &Server{
		// Keep the "http://" scheme: armo.Client.resolveURL forces "https://" onto any
		// baseURL that lacks a scheme prefix, which would break this plain-HTTP fake backend.
		Client: armo.New(backend.URL, backend.Client()),
		Auth:   auth.APIKeyAuthenticator{},
		Cfg:    config.Config{DefaultPageSize: 25, MaxPageSize: 100},
	}

	// Mount the MCP handler behind httptest so the client's Authorization header reaches req.GetExtra().Header.
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		m := mcp.NewServer(&mcp.Implementation{Name: "armo-mcp", Version: "test"}, nil)
		toolServer.Register(m)
		return m
	}, &mcp.StreamableHTTPOptions{Stateless: true})

	front := httptest.NewServer(authHeaderInjector(mcpHandler))
	defer front.Close()

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: front.URL}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "query_vulnerabilities",
		Arguments: map[string]any{"severity": "Critical", "page": 1},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.IsError {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				t.Logf("error content: %s", tc.Text)
			}
		}
		t.Fatalf("tool error: %+v", res.Content)
	}
	sc, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content type = %T", res.StructuredContent)
	}
	if sc["total"].(float64) != 1 {
		t.Errorf("total = %v, want 1", sc["total"])
	}
}

// authHeaderInjector simulates the connector supplying the customer's API key + GUID headers.
func authHeaderInjector(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer key-1")
		r.Header.Set("X-Armo-Customer-Guid", "guid-1")
		next.ServeHTTP(w, r)
	})
}
