package tools

import (
	"context"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/shape"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var incidentsSummaryFields = []string{"guid", "name", "kind", "attributes.incidentStatus", "updatedTime", "clusterName", "signature"}

type QueryIncidentsInput struct {
	AccountInput
	Severity string   `json:"severity,omitempty" jsonschema:"filter by severity: Critical, High, Medium, or Low (capitalized)"`
	Page     int      `json:"page,omitempty" jsonschema:"1-based page number (default 1)"`
	PageSize int      `json:"page_size,omitempty" jsonschema:"items per page (default 25, max 100)"`
	Fields   []string `json:"fields,omitempty" jsonschema:"dotted field paths to include; omit for the summary projection"`
	Full     bool     `json:"full,omitempty" jsonschema:"return full records instead of the summary projection"`
}

func (s *Server) queryIncidents(ctx context.Context, ident armo.Identity, in QueryIncidentsInput) (QueryResult, error) {
	pageNum, pageSize := shape.ClampPage(in.Page, in.PageSize, s.Cfg.DefaultPageSize, s.Cfg.MaxPageSize)
	req := armo.ListRequest{Path: "/runtime/incidents", PageNum: pageNum, PageSize: pageSize}
	// Verified against live cadashboardbe (2026-07-21): /runtime/incidents filters by the
	// "incidentSeverity" field via innerFilters with capitalized values (Critical/High/Medium/Low).
	// A flat "severity" key is silently ignored.
	if in.Severity != "" {
		req.InnerFilters = []map[string]any{{"incidentSeverity": in.Severity}}
	}
	resp, err := s.Client.List(ctx, ident, req)
	if err != nil {
		return QueryResult{}, err
	}
	items, err := shape.Project(resp.Items, effectiveFields(in.Fields, in.Full, incidentsSummaryFields))
	if err != nil {
		return QueryResult{}, err
	}
	return QueryResult{Total: resp.Total, Page: pageNum + 1, PageSize: pageSize, Count: len(items), Items: items}, nil
}

func (s *Server) QueryIncidents(ctx context.Context, req *mcp.CallToolRequest, in QueryIncidentsInput) (*mcp.CallToolResult, QueryResult, error) {
	return s.call(ctx, req, "query_incidents", in, func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		return s.queryIncidents(ctx, ident, in)
	})
}
