package tools

import (
	"context"
	"strings"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/shape"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Field names verified against live cadashboardbe /cloudposture/accounts (2026-07-22).
var cloudAccountsSummaryFields = []string{"accountName", "accountID", "cloudAccountGUID", "reportGUID", "provider", "isConnected", "criticalSeverityResources", "highSeverityResources", "mediumSeverityResources", "lowSeverityResources", "failedResources", "frameworks"}

type ListCloudAccountsInput struct {
	AccountInput
	Provider string   `json:"provider,omitempty" jsonschema:"filter by cloud provider: aws, azure, or gcp (lowercase)"`
	Page     int      `json:"page,omitempty" jsonschema:"1-based page number (default 1)"`
	PageSize int      `json:"page_size,omitempty" jsonschema:"items per page (default 25, max 100)"`
	Fields   []string `json:"fields,omitempty" jsonschema:"dotted field paths to include; omit for the summary projection"`
	Full     bool     `json:"full,omitempty" jsonschema:"return full records instead of the summary projection"`
}

func (s *Server) listCloudAccounts(ctx context.Context, ident armo.Identity, in ListCloudAccountsInput) (QueryResult, error) {
	pageNum, pageSize := shape.ClampPage(in.Page, in.PageSize, s.Cfg.DefaultPageSize, s.Cfg.MaxPageSize)
	req := armo.ListRequest{Path: "/cloudposture/accounts", PageNum: pageNum, PageSize: pageSize}
	if in.Provider != "" {
		req.InnerFilters = []map[string]any{{"provider": strings.ToLower(in.Provider)}}
	}
	resp, err := s.Client.List(ctx, ident, req)
	if err != nil {
		return QueryResult{}, err
	}
	items, err := shape.Project(resp.Items, effectiveFields(in.Fields, in.Full, cloudAccountsSummaryFields))
	if err != nil {
		return QueryResult{}, err
	}
	return QueryResult{Total: resp.Total, Page: pageNum + 1, PageSize: pageSize, Count: len(items), Items: items}, nil
}

func (s *Server) ListCloudAccounts(ctx context.Context, req *mcp.CallToolRequest, in ListCloudAccountsInput) (*mcp.CallToolResult, QueryResult, error) {
	return s.call(ctx, req, "list_cloud_accounts", in, func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		return s.listCloudAccounts(ctx, ident, in)
	})
}
