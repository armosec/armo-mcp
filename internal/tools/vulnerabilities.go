package tools

import (
	"context"
	"strings"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/shape"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var vulnSummaryFields = []string{"name", "id", "severity", "severityScore", "exploitable", "isRelevant", "epssInfo.epss", "workloadsCount"}

type QueryVulnInput struct {
	AccountInput
	Severity string `json:"severity,omitempty" jsonschema:"filter by severity: Critical, High, Medium, or Low"`
	// Workload scope: with cluster/namespace/workload/kind set, the result is the CVEs of those workloads.
	// Combine with list_inventory to build a workload x CVE list one workload at a time.
	Cluster     string   `json:"cluster,omitempty" jsonschema:"only CVEs found in this cluster (exact name)"`
	Namespace   string   `json:"namespace,omitempty" jsonschema:"only CVEs found in workloads of this namespace"`
	Workload    string   `json:"workload,omitempty" jsonschema:"only CVEs found in the workload with this name"`
	Kind        string   `json:"kind,omitempty" jsonschema:"only CVEs found in workloads of this kind, for example deployment or Deployment"`
	CVE         string   `json:"cve,omitempty" jsonschema:"only this CVE, for example CVE-2024-1234"`
	InUse       *bool    `json:"in_use,omitempty" jsonschema:"true: only CVEs whose package is loaded at runtime in some workload of the account; false: only the rest. Account-wide, not per-workload: with a workload filter set, a CVE still counts as in use when another workload loads the same package version"`
	Exploitable *bool    `json:"exploitable,omitempty" jsonschema:"true: only CVEs that are known exploited (CISA KEV) or highly likely to be (EPSS 0.10 or more); false: only the rest"`
	Page        int      `json:"page,omitempty" jsonschema:"1-based page number (default 1)"`
	PageSize    int      `json:"page_size,omitempty" jsonschema:"items per page (default 25, max 100)"`
	Fields      []string `json:"fields,omitempty" jsonschema:"dotted field paths to include; omit for the summary projection"`
	Full        bool     `json:"full,omitempty" jsonschema:"return full records instead of the summary projection"`
}

func (s *Server) queryVulnerabilities(ctx context.Context, ident armo.Identity, in QueryVulnInput) (QueryResult, error) {
	pageNum, pageSize := shape.ClampPage(in.Page, in.PageSize, s.Cfg.DefaultPageSize, s.Cfg.MaxPageSize)

	req := armo.ListRequest{Path: "/vulnerability_v2/vulnerability/list", PageNum: pageNum, PageSize: pageSize}
	if f := vulnFilter(in); len(f) > 0 {
		req.InnerFilters = []map[string]any{f}
	}
	resp, err := s.Client.List(ctx, ident, req)
	if err != nil {
		return QueryResult{}, err
	}
	items, err := shape.Project(resp.Items, effectiveFields(in.Fields, in.Full, vulnSummaryFields))
	if err != nil {
		return QueryResult{}, err
	}
	return QueryResult{Total: resp.Total, Page: pageNum + 1, PageSize: pageSize, Count: len(items), Items: items}, nil
}

// vulnFilter builds one innerFilters entry; the backend ANDs the keys of an entry.
// isRelevant takes Yes/No. exploitable takes the UI's labels: a comma means OR, and
// any other value (including Yes) matches everything.
func vulnFilter(in QueryVulnInput) map[string]any {
	f := map[string]any{}
	for k, v := range map[string]string{
		"severity":  in.Severity,
		"cluster":   in.Cluster,
		"namespace": in.Namespace,
		"workload":  in.Workload,
		// The backend stores kinds lowercase and matches them case-sensitively.
		"kind": strings.ToLower(in.Kind),
		"name": in.CVE,
	} {
		if v != "" {
			f[k] = v
		}
	}
	if in.InUse != nil {
		f["isRelevant"] = yesNo(*in.InUse)
	}
	if in.Exploitable != nil {
		f["exploitable"] = exploitableFilter(*in.Exploitable)
	}
	return f
}

func exploitableFilter(b bool) string {
	if b {
		return "Known Exploited,High Likelihood"
	}
	return "No"
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func (s *Server) QueryVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, in QueryVulnInput) (*mcp.CallToolResult, QueryResult, error) {
	return s.call(ctx, req, "query_vulnerabilities", in, func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		return s.queryVulnerabilities(ctx, ident, in)
	})
}

// effectiveFields mirrors armoctl precedence: explicit fields win, then full=no projection, else the summary set.
func effectiveFields(fields []string, full bool, summary []string) []string {
	switch {
	case len(fields) > 0:
		return fields
	case full:
		return nil
	default:
		return summary
	}
}
