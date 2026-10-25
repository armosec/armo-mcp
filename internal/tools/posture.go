package tools

import (
	"context"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/shape"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Field names verified against live cadashboardbe /posture/controls (2026-07-21):
// controls expose frameworkName (not "framework") and have no "severity"/"scoreFactor";
// scoring is complianceScore/baseScore/score with resource counts.
var postureSummaryFields = []string{"name", "id", "frameworkName", "complianceScore", "baseScore", "status", "section", "affectedResourcesCount", "failedResourcesCount"}

type QueryPostureInput struct {
	AccountInput
	Framework string   `json:"framework,omitempty" jsonschema:"filter controls by compliance framework name"`
	Page      int      `json:"page,omitempty" jsonschema:"1-based page number (default 1)"`
	PageSize  int      `json:"page_size,omitempty" jsonschema:"items per page (default 25, max 100)"`
	Fields    []string `json:"fields,omitempty" jsonschema:"dotted field paths to include; omit for the summary projection"`
	Full      bool     `json:"full,omitempty" jsonschema:"return full records instead of the summary projection"`
}

func (s *Server) queryPosture(ctx context.Context, ident armo.Identity, in QueryPostureInput) (QueryResult, error) {
	pageNum, pageSize := shape.ClampPage(in.Page, in.PageSize, s.Cfg.DefaultPageSize, s.Cfg.MaxPageSize)
	req := armo.ListRequest{Path: "/posture/controls", PageNum: pageNum, PageSize: pageSize}
	if in.Framework != "" {
		req.InnerFilters = []map[string]any{{"frameworkName": in.Framework}}
	}
	resp, err := s.Client.List(ctx, ident, req)
	if err != nil {
		return QueryResult{}, err
	}
	items, err := shape.Project(resp.Items, effectiveFields(in.Fields, in.Full, postureSummaryFields))
	if err != nil {
		return QueryResult{}, err
	}
	return QueryResult{Total: resp.Total, Page: pageNum + 1, PageSize: pageSize, Count: len(items), Items: items}, nil
}

func (s *Server) QueryPosture(ctx context.Context, req *mcp.CallToolRequest, in QueryPostureInput) (*mcp.CallToolResult, QueryResult, error) {
	return s.call(ctx, req, "query_posture", in, func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		return s.queryPosture(ctx, ident, in)
	})
}
