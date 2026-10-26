package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/shape"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// workloadVulnsMaxPageSize bounds the workloads per call; each one costs a backend request.
	workloadVulnsMaxPageSize = 25
	workloadVulnsDefaultSize = 10
	// workloadVulnsMaxPerWorkload bounds the CVE rows kept per workload.
	workloadVulnsMaxPerWorkload = 100
	// workloadVulnsConcurrency bounds the parallel backend requests of one call.
	workloadVulnsConcurrency = 4
)

var workloadVulnFields = []string{"name", "id", "severity", "exploitable", "isRelevant", "epssInfo.epss", "workloadsCount"}

type QueryWorkloadVulnInput struct {
	AccountInput
	Cluster     string   `json:"cluster,omitempty" jsonschema:"only workloads of this cluster (exact name)"`
	Namespace   string   `json:"namespace,omitempty" jsonschema:"only workloads of this namespace"`
	Kind        string   `json:"kind,omitempty" jsonschema:"only workloads of this kind, for example deployment"`
	Workload    string   `json:"workload,omitempty" jsonschema:"only the workload with this name"`
	Severity    string   `json:"severity,omitempty" jsonschema:"only CVEs of this severity: Critical, High, Medium, or Low"`
	CVE         string   `json:"cve,omitempty" jsonschema:"only this CVE, for example CVE-2024-1234"`
	InUse       *bool    `json:"in_use,omitempty" jsonschema:"true: only CVEs in packages loaded at runtime; false: only dormant ones"`
	Exploitable *bool    `json:"exploitable,omitempty" jsonschema:"true: only CVEs that are known exploited (CISA KEV) or highly likely to be (EPSS 0.10 or more); false: only the rest"`
	Page        int      `json:"page,omitempty" jsonschema:"1-based page number over workloads (default 1)"`
	PageSize    int      `json:"page_size,omitempty" jsonschema:"workloads per page (default 10, max 25)"`
	Fields      []string `json:"fields,omitempty" jsonschema:"dotted CVE field paths to include besides the workload columns; omit for the summary projection"`
}

// workloadRef is the part of a /vulnerability_v2/workload/list item that names a workload.
type workloadRef struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
}

// queryWorkloadVulnerabilities pages over workloads and returns one row per workload and CVE.
// Total counts workloads, not rows; Count is the rows on this page.
func (s *Server) queryWorkloadVulnerabilities(ctx context.Context, ident armo.Identity, in QueryWorkloadVulnInput) (QueryResult, error) {
	pageNum, pageSize := shape.ClampPage(in.Page, in.PageSize, workloadVulnsDefaultSize, workloadVulnsMaxPageSize)

	wlReq := armo.ListRequest{Path: "/vulnerability_v2/workload/list", PageNum: pageNum, PageSize: pageSize}
	if f := workloadFilter(in); len(f) > 0 {
		wlReq.InnerFilters = []map[string]any{f}
	}
	wlResp, err := s.Client.List(ctx, ident, wlReq)
	if err != nil {
		return QueryResult{}, err
	}
	workloads := make([]workloadRef, 0, len(wlResp.Items))
	for _, raw := range wlResp.Items {
		var w workloadRef
		if err := json.Unmarshal(raw, &w); err != nil {
			return QueryResult{}, err
		}
		workloads = append(workloads, w)
	}

	fields := in.Fields
	if len(fields) == 0 {
		fields = workloadVulnFields
	}
	perWorkload := make([][]map[string]any, len(workloads))
	truncated := make([]bool, len(workloads))
	errs := make([]error, len(workloads))
	sem := make(chan struct{}, workloadVulnsConcurrency)
	var wg sync.WaitGroup
	for i, w := range workloads {
		wg.Add(1)
		go func(i int, w workloadRef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			perWorkload[i], truncated[i], errs[i] = s.workloadCVEs(ctx, ident, in, w, fields)
		}(i, w)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return QueryResult{}, e
		}
	}

	items := []map[string]any{}
	empty, cut := 0, 0
	for i, rows := range perWorkload {
		if len(rows) == 0 {
			empty++
		}
		if truncated[i] {
			cut++
		}
		items = append(items, rows...)
	}
	res := QueryResult{Total: wlResp.Total, Page: pageNum + 1, PageSize: pageSize, Count: len(items), Items: items}
	res.Note = workloadVulnNote(len(workloads), empty, cut)
	return res, nil
}

// workloadCVEs returns the matching CVEs of one workload, one row per CVE, and whether more existed than were kept.
func (s *Server) workloadCVEs(ctx context.Context, ident armo.Identity, in QueryWorkloadVulnInput, w workloadRef, fields []string) ([]map[string]any, bool, error) {
	f := vulnFilter(QueryVulnInput{
		Cluster: w.Cluster, Namespace: w.Namespace, Workload: w.Name, Kind: w.Kind,
		Severity: in.Severity, CVE: in.CVE, InUse: in.InUse, Exploitable: in.Exploitable,
	})
	resp, err := s.Client.List(ctx, ident, armo.ListRequest{
		Path: "/vulnerability_v2/vulnerability/list", PageNum: 0, PageSize: workloadVulnsMaxPerWorkload,
		InnerFilters: []map[string]any{f},
	})
	if err != nil {
		return nil, false, fmt.Errorf("workload %s/%s: %w", w.Namespace, w.Name, err)
	}
	items, err := shape.Project(resp.Items, fields)
	if err != nil {
		return nil, false, err
	}
	rows := make([]map[string]any, 0, len(items))
	seen := map[any]bool{}
	for _, it := range items {
		// The same CVE in several packages of one workload is one row.
		if name, ok := it["name"]; ok {
			if seen[name] {
				continue
			}
			seen[name] = true
		}
		row := map[string]any{"cluster": w.Cluster, "namespace": w.Namespace, "kind": w.Kind, "workload": w.Name}
		for k, v := range it {
			row[k] = v
		}
		rows = append(rows, row)
	}
	return rows, resp.Total > len(resp.Items), nil
}

func workloadFilter(in QueryWorkloadVulnInput) map[string]any {
	f := map[string]any{}
	for k, v := range map[string]string{
		"cluster":   in.Cluster,
		"namespace": in.Namespace,
		"kind":      strings.ToLower(in.Kind),
		"name":      in.Workload,
	} {
		if v != "" {
			f[k] = v
		}
	}
	return f
}

func workloadVulnNote(workloads, empty, cut int) string {
	parts := []string{fmt.Sprintf("page covers %d workloads; total counts workloads, not rows", workloads)}
	if empty > 0 {
		parts = append(parts, fmt.Sprintf("%d of them have no matching CVEs", empty))
	}
	if cut > 0 {
		parts = append(parts, fmt.Sprintf("%d workloads have more than %d matching CVEs, only the first %d are shown (narrow with severity or cve)", cut, workloadVulnsMaxPerWorkload, workloadVulnsMaxPerWorkload))
	}
	return strings.Join(parts, "; ")
}

func (s *Server) QueryWorkloadVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, in QueryWorkloadVulnInput) (*mcp.CallToolResult, QueryResult, error) {
	return s.call(ctx, req, "query_workload_vulnerabilities", in, func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		return s.queryWorkloadVulnerabilities(ctx, ident, in)
	})
}
