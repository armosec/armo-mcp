package tools

import (
	"context"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/shape"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Field names verified against live cadashboardbe /cloudposture/frameworks (2026-07-22).
var cloudComplianceSummaryFields = []string{"name", "complianceScorev1", "failedControls", "totalControls", "typeTags"}

type QueryCloudComplianceInput struct {
	AccountInput
	Page     int      `json:"page,omitempty" jsonschema:"1-based page number (default 1)"`
	PageSize int      `json:"page_size,omitempty" jsonschema:"items per page (default 25, max 100)"`
	Fields   []string `json:"fields,omitempty" jsonschema:"dotted field paths to include; omit for the summary projection"`
	Full     bool     `json:"full,omitempty" jsonschema:"return full records instead of the summary projection"`
}

func (s *Server) queryCloudCompliance(ctx context.Context, ident armo.Identity, in QueryCloudComplianceInput) (QueryResult, error) {
	pageNum, pageSize := shape.ClampPage(in.Page, in.PageSize, s.Cfg.DefaultPageSize, s.Cfg.MaxPageSize)
	resp, err := s.Client.List(ctx, ident, armo.ListRequest{Path: "/cloudposture/frameworks", PageNum: pageNum, PageSize: pageSize})
	if err != nil {
		return QueryResult{}, err
	}
	items, err := shape.Project(resp.Items, effectiveFields(in.Fields, in.Full, cloudComplianceSummaryFields))
	if err != nil {
		return QueryResult{}, err
	}
	return QueryResult{Total: resp.Total, Page: pageNum + 1, PageSize: pageSize, Count: len(items), Items: items}, nil
}

func (s *Server) QueryCloudCompliance(ctx context.Context, req *mcp.CallToolRequest, in QueryCloudComplianceInput) (*mcp.CallToolResult, QueryResult, error) {
	return s.call(ctx, req, "query_cloud_compliance", in, func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		return s.queryCloudCompliance(ctx, ident, in)
	})
}
