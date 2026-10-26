package tools

import (
	"net/http"
	"sync"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/auth"
	"github.com/armosec/armo-mcp/internal/cache"
	"github.com/armosec/armo-mcp/internal/config"
	"github.com/armosec/armo-mcp/internal/limit"
	"github.com/armosec/armo-mcp/internal/metrics"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Server struct {
	Client *armo.Client
	Auth   auth.Authenticator
	Cfg    config.Config

	// Limiter, Cache and Metrics are all optional (nil-able): unset means the
	// corresponding stage of the call funnel (internal/tools/call.go) is
	// skipped, so stdio mode and unit tests work without wiring any of them.
	Limiter *limit.Limiter
	Cache   *cache.Cache[QueryResult]
	Metrics *metrics.Metrics
	// Accounts caches each OAuth token's account list with names. Nil looks
	// the list up on every call.
	Accounts *cache.Cache[[]armo.Account]

	// Name-lookup state, set up on first use: token hashes whose lookup failed
	// recently, and the lookups in flight.
	accountOnce     sync.Once
	accountFailures *cache.Cache[struct{}]
	accountMu       sync.Mutex
	accountInflight map[string]*accountLookup
}

// resolveIdentity extracts the caller's identity for a tool call. It reads the
// request's HTTP headers when present (HTTP transport) and tolerates their
// absence (stdio transport, where GetExtra() and its Header are nil) — the
// configured Authenticator decides what to do with a nil header set.
func (s *Server) resolveIdentity(req *mcp.CallToolRequest) (armo.Identity, error) {
	var h http.Header
	if ex := req.GetExtra(); ex != nil {
		h = ex.Header
	}
	return s.Auth.Resolve(h)
}

type QueryResult struct {
	Total    int              `json:"total" jsonschema:"total matching items on the backend"`
	Page     int              `json:"page" jsonschema:"1-based page returned"`
	PageSize int              `json:"page_size" jsonschema:"page size used"`
	Count    int              `json:"count" jsonschema:"number of items in this page"`
	Items    []map[string]any `json:"items" jsonschema:"the projected result items"`
	Account  *AccountRef      `json:"account,omitempty" jsonschema:"the ARMO account these results are from"`
	Note     string           `json:"note,omitempty" jsonschema:"a caveat about these results, when there is one"`
}

// Register wires every tool onto the given MCP server. Later tasks add more AddTool calls here.
func (s *Server) Register(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{
		Name:        "query_vulnerabilities",
		Description: "Query the caller's ARMO CVE findings. Read-only. Supports filters for severity, CVE, in-use, exploitable and workload scope (cluster, namespace, workload, kind), paging, and field selection. To list the CVEs of each workload, take workloads from list_inventory and call this once per workload with in_use/exploitable set as needed.",
	}, s.QueryVulnerabilities)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "query_workload_vulnerabilities",
		Description: "List the CVEs of the caller's workloads, one row per workload and CVE. Read-only. Pages over workloads (default 10, max 25 per call), so a full export is a few calls: keep calling with the next page until you have covered total workloads. Supports workload scope (cluster, namespace, kind, workload) and CVE filters (severity, cve, in_use, exploitable). Note: in_use and the isRelevant column are account-wide (the package is loaded in some workload), not per-workload.",
	}, s.QueryWorkloadVulnerabilities)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "query_posture",
		Description: "Query the caller's ARMO Kubernetes posture controls. Read-only. Supports framework filter, paging, and field selection.",
	}, s.QueryPosture)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "query_incidents",
		Description: "Query the caller's ARMO runtime incidents. Read-only. Supports severity filter, paging, and field selection.",
	}, s.QueryIncidents)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "query_images",
		Description: "Query the caller's ARMO container image inventory with vulnerability rollups. Read-only. Supports paging and field selection.",
	}, s.QueryImages)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "query_risks",
		Description: "Query the caller's ARMO security risks. Read-only. Supports severity filter, paging, and field selection.",
	}, s.QueryRisks)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "list_inventory",
		Description: "List the caller's ARMO asset inventory (workloads and cloud resources). Read-only. Supports paging and field selection.",
	}, s.ListInventory)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "list_repositories",
		Description: "List the caller's ARMO-connected source repositories with IaC/repository posture. Read-only. Supports paging and field selection.",
	}, s.ListRepositories)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "query_attack_chains",
		Description: "Query the caller's ARMO attack chains (attack paths toward sensitive assets). Read-only. Supports paging and field selection.",
	}, s.QueryAttackChains)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "list_cloud_accounts",
		Description: "List the caller's connected cloud accounts (CSPM) with posture rollups. Read-only. Supports provider filter, paging, field selection.",
	}, s.ListCloudAccounts)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "query_cloud_posture",
		Description: "Query the caller's cloud misconfiguration controls (CSPM). Read-only. Supports severity + framework filters, paging, field selection.",
	}, s.QueryCloudPosture)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "query_cloud_compliance",
		Description: "Query the caller's cloud compliance framework scores (CSPM). Read-only. Supports paging and field selection.",
	}, s.QueryCloudCompliance)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "list_accounts",
		Description: "List the ARMO accounts the caller can query, with each account's name and customerGUID; active marks the account signed in to, which tools use by default. Pass a name or customerGUID as another tool's account parameter to query that account. Read-only.",
	}, s.ListAccounts)
	s.registerResources(m)
}
