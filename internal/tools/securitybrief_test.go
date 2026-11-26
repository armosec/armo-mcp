package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/auth"
	"github.com/armosec/armo-mcp/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The expected value is the example in Claude's MCP Apps documentation.
func TestClaudeUIDomainMatchesDocumentedExample(t *testing.T) {
	got := claudeUIDomain("https://example.com/mcp")
	if want := "c3d80a4ed901ee05b21755a88273b4a4.claudemcpcontent.com"; got != want {
		t.Errorf("claudeUIDomain = %q, want %q", got, want)
	}
}

// briefBackend fakes the four list endpoints the brief counts. failing names
// path suffixes that answer 500.
func briefBackend(failing ...string) http.HandlerFunc {
	vulnTotals := map[string]int{"Critical": 4, "High": 30, "Medium": 200, "Low": 1000}
	return func(w http.ResponseWriter, r *http.Request) {
		for _, f := range failing {
			if strings.HasSuffix(r.URL.Path, f) {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		b, _ := io.ReadAll(r.Body)
		var body struct {
			InnerFilters []map[string]any `json:"innerFilters"`
		}
		_ = json.Unmarshal(b, &body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulnerability_v2/vulnerability/list"):
			sev := ""
			if len(body.InnerFilters) > 0 {
				sev, _ = body.InnerFilters[0]["severity"].(string)
			}
			_, _ = fmt.Fprintf(w, `{"response":[{"name":"CVE-1"}],"total":{"value":%d}}`, vulnTotals[sev])
		case strings.HasSuffix(r.URL.Path, "/runtime/incidents"):
			_, _ = io.WriteString(w, `{"response":[{"name":"i"}],"total":{"value":7}}`)
		case strings.HasSuffix(r.URL.Path, "/attackchains"):
			_, _ = io.WriteString(w, `{"response":{"attackChains":[{"name":"c"}]},"total":{"value":2}}`)
		case strings.HasSuffix(r.URL.Path, "/securityrisks/list"):
			_, _ = io.WriteString(w, `{"response":[{"securityRiskName":"r"}],"total":{"value":18}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// briefKey names a row of the brief: "vulnerabilities/Critical", "incidents".
func briefKey(item map[string]any) string {
	k, _ := item["section"].(string)
	if sev, ok := item["severity"].(string); ok {
		k += "/" + sev
	}
	return k
}

func TestSecurityBriefCountsEachSection(t *testing.T) {
	s, closeFn := newTestServer(t, briefBackend())
	defer closeFn()

	out, err := s.securityBrief(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"vulnerabilities/Critical": 4, "vulnerabilities/High": 30, "vulnerabilities/Medium": 200, "vulnerabilities/Low": 1000,
		"incidents": 7, "attack_chains": 2, "risks": 18,
	}
	if out.Total != len(want) || out.Count != len(want) || len(out.Items) != len(want) {
		t.Fatalf("envelope = total %d count %d items %d, want %d each", out.Total, out.Count, len(out.Items), len(want))
	}
	for _, item := range out.Items {
		k := briefKey(item)
		if item["total"] != want[k] {
			t.Errorf("%s total = %v, want %d", k, item["total"], want[k])
		}
	}
	if out.Note != "" {
		t.Errorf("note = %q, want none", out.Note)
	}
}

func TestSecurityBriefMarksFailedSectionUnavailable(t *testing.T) {
	s, closeFn := newTestServer(t, briefBackend("/runtime/incidents"))
	defer closeFn()

	out, err := s.securityBrief(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"})
	if err != nil {
		t.Fatalf("one failed section must not fail the brief: %v", err)
	}
	if out.Note != briefSectionsUnavailable {
		t.Errorf("note = %q", out.Note)
	}
	for _, item := range out.Items {
		_, hasTotal := item["total"]
		if briefKey(item) == "incidents" {
			if item["unavailable"] != true || hasTotal {
				t.Errorf("incidents row = %v, want unavailable with no total", item)
			}
		} else if !hasTotal {
			t.Errorf("%s lost its total: %v", briefKey(item), item)
		}
	}
}

func TestSecurityBriefFailsWhenEverySectionFails(t *testing.T) {
	s, closeFn := newTestServer(t, briefBackend("/vulnerability_v2/vulnerability/list", "/runtime/incidents", "/attackchains", "/securityrisks/list"))
	defer closeFn()

	if _, err := s.securityBrief(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}); err == nil {
		t.Fatal("want an error when no section could be loaded")
	}
}

// connectInMemory registers s on an MCP server and returns a client session,
// so assertions run on what actually crosses the wire.
func connectInMemory(t *testing.T, s *Server) *mcp.ClientSession {
	t.Helper()
	m := mcp.NewServer(&mcp.Implementation{Name: "armo-mcp", Version: "test"}, nil)
	s.Register(m)
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := m.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestSecurityBriefToolPointsAtItsView(t *testing.T) {
	cs := connectInMemory(t, &Server{})
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var tool *mcp.Tool
	for _, tl := range lt.Tools {
		if tl.Name == "show_security_brief" {
			tool = tl
		} else if len(tl.Meta) != 0 {
			t.Errorf("%s has _meta %v; only show_security_brief has a view", tl.Name, tl.Meta)
		}
	}
	if tool == nil {
		t.Fatal("show_security_brief is not registered")
	}
	ui, _ := tool.Meta["ui"].(map[string]any)
	if ui["resourceUri"] != "ui://armo/security-brief" {
		t.Errorf("_meta.ui.resourceUri = %v", ui["resourceUri"])
	}
	if tool.Meta["ui/resourceUri"] != "ui://armo/security-brief" {
		t.Errorf(`_meta["ui/resourceUri"] = %v`, tool.Meta["ui/resourceUri"])
	}
}

func readBriefResource(t *testing.T, s *Server) *mcp.ResourceContents {
	t.Helper()
	res, err := connectInMemory(t, s).ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "ui://armo/security-brief"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("contents = %d, want 1", len(res.Contents))
	}
	return res.Contents[0]
}

func TestSecurityBriefResourceIsAnMCPApp(t *testing.T) {
	const serverURL = "https://mcp.example.test/mcp"
	c := readBriefResource(t, &Server{Cfg: config.Config{MCPResourceURL: serverURL}})

	if c.URI != "ui://armo/security-brief" || c.MIMEType != "text/html;profile=mcp-app" {
		t.Errorf("uri %q mime %q", c.URI, c.MIMEType)
	}
	if !strings.HasPrefix(c.Text, "<!DOCTYPE html>") {
		t.Errorf("view does not start with a doctype: %.40q", c.Text)
	}
	ui, _ := c.Meta["ui"].(map[string]any)
	if ui["domain"] != claudeUIDomain(serverURL) {
		t.Errorf("_meta.ui.domain = %v, want %s", ui["domain"], claudeUIDomain(serverURL))
	}
	csp, _ := ui["csp"].(map[string]any)
	domains, _ := csp["resourceDomains"].([]any)
	if len(domains) != 1 || domains[0] != "https://unpkg.com" {
		t.Errorf("_meta.ui.csp.resourceDomains = %v", csp["resourceDomains"])
	}
}

// With no public URL configured (stdio, local runs) the domain is left out:
// a made-up one would fail the host's validation.
func TestSecurityBriefResourceOmitsDomainWithoutServerURL(t *testing.T) {
	c := readBriefResource(t, &Server{})
	ui, _ := c.Meta["ui"].(map[string]any)
	if _, ok := ui["domain"]; ok {
		t.Errorf("_meta.ui.domain = %v, want it absent", ui["domain"])
	}
}

func TestSecurityBriefResourceIsListed(t *testing.T) {
	lr, err := connectInMemory(t, &Server{}).ListResources(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range lr.Resources {
		if r.URI == "ui://armo/security-brief" {
			if r.MIMEType != "text/html;profile=mcp-app" {
				t.Errorf("mime = %q", r.MIMEType)
			}
			return
		}
	}
	t.Error("ui://armo/security-brief is not in resources/list")
}

// The view is static HTML that the Go compiler cannot check, so these guard
// the two things that break it silently: a script origin the CSP does not
// allow, and a call to a tool the server does not have.
func TestSecurityBriefViewMatchesServer(t *testing.T) {
	imports := regexp.MustCompile(`from "(https://[^/"]+)/[^"]*"`).FindAllStringSubmatch(securityBriefHTML, -1)
	if len(imports) == 0 {
		t.Fatal("the view imports no MCP Apps client")
	}
	for _, m := range imports {
		if m[1] != extAppsScriptOrigin {
			t.Errorf("view loads a script from %s, which the resource CSP does not allow", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`(?:src|href)="(https?://[^"]+)"`).FindAllStringSubmatch(securityBriefHTML, -1) {
		t.Errorf("view loads %s, which the resource CSP does not allow", m[1])
	}

	lt, err := connectInMemory(t, &Server{}).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, tl := range lt.Tools {
		registered[tl.Name] = true
	}
	calls := regexp.MustCompile(`call\("([a-z_]+)"`).FindAllStringSubmatch(securityBriefHTML, -1)
	if len(calls) < 5 {
		t.Fatalf("found %d tool calls in the view, want at least 5", len(calls))
	}
	for _, m := range calls {
		if !registered[m[1]] {
			t.Errorf("view calls %q, which is not a registered tool", m[1])
		}
	}
}

// End to end through the call funnel: the result is the usual envelope, with
// the account it came from.
func TestShowSecurityBriefReturnsEnvelope(t *testing.T) {
	s, closeFn := newTestServer(t, briefBackend())
	defer closeFn()
	s.Auth = auth.StaticAuthenticator{ID: armo.Identity{CustomerGUID: "guid-1", APIKey: "k"}}

	res, err := connectInMemory(t, s).CallTool(context.Background(), &mcp.CallToolParams{Name: "show_security_brief", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	sc, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content type = %T", res.StructuredContent)
	}
	if sc["total"].(float64) != 7 || len(sc["items"].([]any)) != 7 {
		t.Errorf("envelope = %v", sc)
	}
	if acct, _ := sc["account"].(map[string]any); acct["customerGUID"] != "guid-1" {
		t.Errorf("account = %v", sc["account"])
	}
	if len(res.Content) == 0 {
		t.Error("no text content for hosts that do not render the view")
	}
}
