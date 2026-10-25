package tools

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/shape"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Field names verified against live cadashboardbe /cloudposture/controls (2026-07-22).
// NOTE: cloud control severity is LOWERCASE (critical/high/medium/low); the backend
// returns HTTP 500 on capitalized values, so we lowercase before sending.
var cloudPostureSummaryFields = []string{"cloudControlName", "cloudControlID", "frameworkName", "severity", "status", "complianceScore", "affectedResourcesCount", "failedResourcesCount", "section"}

type QueryCloudPostureInput struct {
	AccountInput
	Severity   string   `json:"severity,omitempty" jsonschema:"filter by severity: critical, high, medium, or low (lowercase)"`
	Framework  string   `json:"framework,omitempty" jsonschema:"filter by cloud compliance framework name (e.g. cis_1.4)"`
	ReportGUID string   `json:"report_guid,omitempty" jsonschema:"advanced: scan report GUID(s) to scope the controls to, comma-separated (from a cloud account's reportGUID). Omit to scope automatically to the latest scan of every cloud account."`
	Page       int      `json:"page,omitempty" jsonschema:"1-based page number (default 1)"`
	PageSize   int      `json:"page_size,omitempty" jsonschema:"items per page (default 25, max 100)"`
	Fields     []string `json:"fields,omitempty" jsonschema:"dotted field paths to include; omit for the summary projection"`
	Full       bool     `json:"full,omitempty" jsonschema:"return full records instead of the summary projection"`
}

func (s *Server) queryCloudPosture(ctx context.Context, ident armo.Identity, in QueryCloudPostureInput) (QueryResult, error) {
	pageNum, pageSize := shape.ClampPage(in.Page, in.PageSize, s.Cfg.DefaultPageSize, s.Cfg.MaxPageSize)

	// Cloud control summaries are stored per scan report. Filtering by reportGUID
	// is the only scope the backend can serve efficiently — an unfiltered query
	// (and, notably, one filtered only by severity/framework/cloudAccountGUID)
	// scans every historical report and times out. When the caller doesn't pin a
	// report, default to the latest scan of every cloud account, matching the
	// console's cloud-posture view.
	reportScope := in.ReportGUID
	if reportScope != "" {
		// Tolerate a caller passing spaces in a comma-separated list, e.g. "r1, r2".
		reportScope = strings.ReplaceAll(reportScope, " ", "")
	}
	if reportScope == "" {
		guids, err := s.latestCloudReportGUIDs(ctx, ident)
		if err != nil {
			return QueryResult{}, err
		}
		if len(guids) == 0 {
			return QueryResult{Total: 0, Page: pageNum + 1, PageSize: pageSize, Count: 0, Items: []map[string]any{}}, nil
		}
		reportScope = strings.Join(guids, ",")
	}

	req := armo.ListRequest{Path: "/cloudposture/controls", PageNum: pageNum, PageSize: pageSize}
	f := map[string]any{"reportGUID": reportScope}
	if in.Severity != "" {
		f["severity"] = strings.ToLower(in.Severity)
	}
	if in.Framework != "" {
		f["frameworkName"] = in.Framework
	}
	req.InnerFilters = []map[string]any{f}
	resp, err := s.Client.List(ctx, ident, req)
	if err != nil {
		return QueryResult{}, err
	}
	items, err := shape.Project(resp.Items, effectiveFields(in.Fields, in.Full, cloudPostureSummaryFields))
	if err != nil {
		return QueryResult{}, err
	}
	return QueryResult{Total: resp.Total, Page: pageNum + 1, PageSize: pageSize, Count: len(items), Items: items}, nil
}

// latestCloudReportGUIDs returns the current scan report GUID of every cloud
// account (deduplicated). Filtering /cloudposture/controls by these bounds the
// query to the latest posture, the same scope the console shows.
//
// A tenant can have more cloud accounts than fit on one page, so this paginates
// until every account has been fetched (guarded by a hard cap on iterations in
// case the backend ever misreports Total, to avoid looping forever).
func (s *Server) latestCloudReportGUIDs(ctx context.Context, ident armo.Identity) ([]string, error) {
	const maxPages = 1000
	pageSize := s.Cfg.MaxPageSize
	if pageSize <= 0 {
		// Guard against a misconfigured MaxPageSize: a 0 page size would fetch 0
		// accounts and silently yield an empty report scope — the exact silent
		// failure this scoping fix exists to prevent.
		pageSize = 100
	}
	seen := map[string]bool{}
	var guids []string
	fetched := 0
	for page := 0; page < maxPages; page++ {
		resp, err := s.Client.List(ctx, ident, armo.ListRequest{Path: "/cloudposture/accounts", PageNum: page, PageSize: pageSize})
		if err != nil {
			return nil, err
		}
		if len(resp.Items) == 0 {
			break // no more accounts, regardless of what Total claims
		}
		for _, raw := range resp.Items {
			var acct struct {
				ReportGUID string `json:"reportGUID"`
			}
			if err := json.Unmarshal(raw, &acct); err != nil {
				continue // skip an unparseable account row rather than fail the whole query
			}
			if acct.ReportGUID != "" && !seen[acct.ReportGUID] {
				seen[acct.ReportGUID] = true
				guids = append(guids, acct.ReportGUID)
			}
		}
		fetched += len(resp.Items)
		// Decide whether more pages remain. Don't rely on Total alone: armo.Client
		// leaves Total=0 when the response envelope omits it, which would stop us
		// after the first (possibly full) page. When Total is known, page until we
		// have it all; otherwise treat a short page as the last one.
		if resp.Total > 0 {
			if fetched >= resp.Total {
				break
			}
		} else if len(resp.Items) < pageSize {
			break
		}
	}
	return guids, nil
}

func (s *Server) QueryCloudPosture(ctx context.Context, req *mcp.CallToolRequest, in QueryCloudPostureInput) (*mcp.CallToolResult, QueryResult, error) {
	return s.call(ctx, req, "query_cloud_posture", in, func(ctx context.Context, ident armo.Identity) (QueryResult, error) {
		return s.queryCloudPosture(ctx, ident, in)
	})
}
