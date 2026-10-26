//go:build systemtest

// Package system holds black-box system tests that run against a DEPLOYED
// armo-mcp endpoint. Build-tagged (`systemtest`) so it never runs in the unit
// `go test ./...` path. Run with:
//
//	go test -tags systemtest ./test/system/... -v
//
// after exporting ARMOMCP_SYSTEST_ENDPOINT / _GUID / _KEY.
package system

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// wantTools is the exact read-only tool set armo-mcp advertises.
var wantTools = []string{
	"query_vulnerabilities", "query_posture", "query_incidents", "query_risks",
	"query_images", "list_inventory", "list_repositories", "query_attack_chains",
	"list_cloud_accounts", "query_cloud_posture", "query_cloud_compliance",
	"list_accounts", "query_workload_vulnerabilities",
}

type config struct {
	Endpoint string
	GUID     string
	Key      string
}

// loadConfig reads the test-tenant credentials from the environment and skips
// the test (never fails) when they are absent, so an unconfigured run is green.
func loadConfig(t *testing.T) config {
	t.Helper()
	c := config{
		Endpoint: os.Getenv("ARMOMCP_SYSTEST_ENDPOINT"),
		GUID:     os.Getenv("ARMOMCP_SYSTEST_GUID"),
		Key:      os.Getenv("ARMOMCP_SYSTEST_KEY"),
	}
	if c.Endpoint == "" || c.GUID == "" || c.Key == "" {
		t.Skip("system test skipped: set ARMOMCP_SYSTEST_ENDPOINT/_GUID/_KEY to run")
	}
	return c
}

// headerRT injects a fixed set of headers on every request.
type headerRT struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h headerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return h.base.RoundTrip(r)
}

func twoHeaderRT(key, guid string) http.RoundTripper {
	return headerRT{http.DefaultTransport, map[string]string{
		"Authorization":        "Bearer " + key,
		"X-Armo-Customer-Guid": guid,
	}}
}

func packedRT(guidKey string) http.RoundTripper {
	return headerRT{http.DefaultTransport, map[string]string{
		"Authorization": "Bearer " + guidKey,
	}}
}

func rawRT(headers map[string]string) http.RoundTripper {
	return headerRT{http.DefaultTransport, headers}
}

// connect opens an MCP session over Streamable HTTP with the given transport
// auth, and closes it at test end.
func connect(t *testing.T, endpoint string, rt http.RoundTripper) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	client := mcp.NewClient(&mcp.Implementation{Name: "armo-mcp-systemtest", Version: "1.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		HTTPClient:           &http.Client{Transport: rt, Timeout: 45 * time.Second},
		DisableStandaloneSSE: true,
	}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect to %s failed: %v", endpoint, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// callTool invokes a tool with a fresh 45s context and returns the raw result.
func callTool(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s) transport error: %v", name, err)
	}
	return res
}

// contentText flattens a tool result's text content for substring assertions.
func contentText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
