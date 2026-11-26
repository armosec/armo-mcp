package tools

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"sync"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The security brief is an MCP App (SEP-1865, extension io.modelcontextprotocol/ui):
// show_security_brief points at a ui:// resource, and a host that supports the
// extension renders that HTML next to the tool result. Hosts that do not
// support it ignore the _meta and show the result as they do for any tool.
//
// The Go SDK has no helpers for the extension (the official ones are
// TypeScript only), so the _meta fields are written by hand here.
const (
	securityBriefTool = "show_security_brief"
	securityBriefURI  = "ui://armo/security-brief"

	// mcpAppMIMEType marks a resource as an MCP App view.
	mcpAppMIMEType = "text/html;profile=mcp-app"

	// extAppsScriptOrigin is where the view loads the MCP Apps client from. The
	// view's sandbox blocks every origin that the resource's CSP does not name.
	extAppsScriptOrigin = "https://unpkg.com"

	// claudeContentSuffix is the host Claude serves view content from.
	claudeContentSuffix = ".claudemcpcontent.com"
)

//go:embed ui/security-brief.html
var securityBriefHTML string

var briefSeverities = []string{"Critical", "High", "Medium", "Low"}

// briefSectionsUnavailable is the note on a brief that is missing sections.
const briefSectionsUnavailable = "Some sections could not be loaded; their rows are marked unavailable and have no total."

// claudeUIDomain is the _meta.ui.domain Claude expects for a view: the first 32
// hex characters of the SHA-256 of the server's public URL, under
// claudemcpcontent.com. The URL is hashed exactly as given, so it must be the
// URL users enter for the connector, path included.
func claudeUIDomain(serverURL string) string {
	sum := sha256.Sum256([]byte(serverURL))
	return hex.EncodeToString(sum[:])[:32] + claudeContentSuffix
}

// securityBriefToolMeta links the tool to its view. The nested key is the
// current form; the flat one is the deprecated form the official helpers still
// emit for older hosts.
func securityBriefToolMeta() mcp.Meta {
	return mcp.Meta{
		"ui":             map[string]any{"resourceUri": securityBriefURI},
		"ui/resourceUri": securityBriefURI,
	}
}

// securityBriefResourceMeta is the _meta of the view's content: the origins the
// sandbox may load from and, when the public URL is configured, Claude's domain.
// Without the URL the domain is left out instead of guessed.
func (s *Server) securityBriefResourceMeta() mcp.Meta {
	ui := map[string]any{
		"csp":           map[string]any{"resourceDomains": []string{extAppsScriptOrigin}},
		"prefersBorder": false,
	}
	if s.Cfg.MCPResourceURL != "" {
		ui["domain"] = claudeUIDomain(s.Cfg.MCPResourceURL)
	}
	return mcp.Meta{"ui": ui}
}

func (s *Server) registerSecurityBrief(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{
		Name:        securityBriefTool,
		Description: "Show the caller's ARMO security brief: CVE counts by severity and the number of runtime incidents, attack paths and security risks, one row per section. Read-only. In clients that support MCP Apps this opens an interactive view with the CVE table, incidents, attack paths and risks; elsewhere it returns the counts only.",
		Meta:        securityBriefToolMeta(),
	}, s.ShowSecurityBrief)

	m.AddResource(
		&mcp.Resource{
			URI:         securityBriefURI,
			Name:        "security-brief",
			Description: "Interactive view for show_security_brief (MCP App).",
			MIMEType:    mcpAppMIMEType,
		},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{
					URI:      securityBriefURI,
					MIMEType: mcpAppMIMEType,
					Text:     securityBriefHTML,
					Meta:     s.securityBriefResourceMeta(),
				}},
			}, nil
		},
	)
}

type ShowSecurityBriefInput struct {
	AccountInput
}

// securityBrief counts each section of the brief with one single-row query per
// count, run together. A section that fails is marked unavailable so the rest
// of the brief still shows; if every section fails, the first error is returned.
func (s *Server) securityBrief(ctx context.Context, ident armo.Identity) (QueryResult, error) {
	type section struct {
		item  map[string]any
		count func() (QueryResult, error)
	}
	name := []string{"name"}
	var sections []section
	for _, sev := range briefSeverities {
		sections = append(sections, section{
			item: map[string]any{"section": "vulnerabilities", "severity": sev},
			count: func() (QueryResult, error) {
				return s.queryVulnerabilities(ctx, ident, QueryVulnInput{Severity: sev, PageSize: 1, Fields: name})
			},
		})
	}
	sections = append(sections,
		section{map[string]any{"section": "incidents"}, func() (QueryResult, error) {
			return s.queryIncidents(ctx, ident, QueryIncidentsInput{PageSize: 1, Fields: name})
		}},
		section{map[string]any{"section": "attack_chains"}, func() (QueryResult, error) {
			return s.queryAttackChains(ctx, ident, QueryAttackChainsInput{PageSize: 1, Fields: name})
		}},
		section{map[string]any{"section": "risks"}, func() (QueryResult, error) {
			return s.queryRisks(ctx, ident, QueryRisksInput{PageSize: 1, Fields: []string{"securityRiskName"}})
		}},
	)

	errs := make([]error, len(sections))
	var wg sync.WaitGroup
	for i, sec := range sections {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := sec.count()
			if err != nil {
				errs[i] = err
				sec.item["unavailable"] = true
				return
			}
			sec.item["total"] = res.Total
		}()
	}
	wg.Wait()

	items := make([]map[string]any, len(sections))
	failed := 0
	var firstErr error
	for i, sec := range sections {
		items[i] = sec.item
		if errs[i] != nil {
			failed++
			if firstErr == nil {
				firstErr = errs[i]
			}
		}
	}
	if failed == len(sections) {
		return QueryResult{}, firstErr
	}
	out := QueryResult{Total: len(items), Page: 1, PageSize: len(items), Count: len(items), Items: items}
	if failed > 0 {
		out.Note = briefSectionsUnavailable
	}
	return out, nil
}

func (s *Server) ShowSecurityBrief(ctx context.Context, req *mcp.CallToolRequest, in ShowSecurityBriefInput) (*mcp.CallToolResult, QueryResult, error) {
	return s.call(ctx, req, securityBriefTool, in, s.securityBrief)
}
