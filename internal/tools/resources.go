package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const cheatsheetText = `# ARMO MCP field & enum cheatsheet

## Severity values
- query_vulnerabilities, query_incidents, query_risks: Capitalized (Critical, High, Medium, Low)
- Cloud (query_cloud_posture): lowercase — critical, high, medium, low

## Selecting fields
- Omit "fields" to get a compact summary projection (recommended, small).
- Pass "fields" as dotted paths (e.g. "attributes.incidentStatus") to pick specific fields.
- Pass "full": true only when you truly need every field (large responses).

## Paging
- "page" is 1-based (default 1). "page_size" defaults to 25, max 100.
- Each result includes total, page, page_size, count. Increase "page" to get more.

## Tools
- query_vulnerabilities: filters "severity" (Critical/High/Medium/Low), "cve", "cluster", "namespace", "workload", "kind", "in_use" (true/false) and "exploitable" (true: known exploited or EPSS 0.10+). Workload filters list the CVEs of that workload.
- query_workload_vulnerabilities: one row per workload and CVE. Same scope and CVE filters as query_vulnerabilities (cluster, namespace, kind, workload; severity, cve, in_use, exploitable). Pages over workloads: "page_size" is workloads (default 10, max 25) and "total" counts workloads. For a full export keep calling until you have covered total workloads. With "cve" set, the pages hold only the workloads that have that CVE, so "which workloads have CVE-X" is one call.
- query_posture: filter "framework" (a compliance framework name)
- query_incidents: filter "severity" (Critical/High/Medium/Low)
- query_risks: filter "severity" (Critical/High/Medium/Low)
- query_images: no filter (paging + fields)
- list_inventory: no filter (paging + fields)
- list_repositories: no filter (paging + fields)
- query_attack_chains: no filter (paging + fields)
- list_cloud_accounts: filter "provider" (aws/azure/gcp, lowercase)
- query_cloud_posture: filter "severity" (lowercase: critical/high/medium/low) and/or "framework"
- query_cloud_compliance: no filter (paging + fields)
- list_accounts: no parameters; lists the accounts the user can query, by name and customerGUID

Every tool except list_accounts takes "account": a customerGUID or exact name from
list_accounts. Omit it for the account the user signed in to. Results carry
"account" with the customerGUID and name they came from.
`

func (s *Server) registerResources(m *mcp.Server) {
	m.AddResource(
		&mcp.Resource{
			URI:         "armo://cheatsheets/fields",
			Name:        "field-cheatsheet",
			Description: "Valid filter values, field-selection rules, and paging semantics for ARMO MCP tools.",
			MIMEType:    "text/markdown",
		},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{
					URI:      "armo://cheatsheets/fields",
					MIMEType: "text/markdown",
					Text:     cheatsheetText,
				}},
			}, nil
		},
	)
}
