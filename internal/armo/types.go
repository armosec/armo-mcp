package armo

import "encoding/json"

type Identity struct {
	CustomerGUID string
	APIKey       string
	// Bearer is an OAuth access token, sent instead of x-api-key when set.
	Bearer string
	// Tenants are the accounts the token's tenantIds claim lists, besides
	// CustomerGUID. The backend accepts a request for any of them.
	Tenants []string
	// ClientUA is the calling assistant's User-Agent, forwarded to the backend
	// as X-MCP-Client so it can tell which client made the call. Empty when
	// the transport has no headers.
	ClientUA string
}

// Account is one ARMO account (Frontegg tenant) the caller belongs to.
type Account struct {
	GUID string `json:"customerGUID"`
	Name string `json:"customerName"`
}

type ListRequest struct {
	Path         string
	PageNum      int
	PageSize     int
	InnerFilters []map[string]any
	Extra        map[string]any
	// ResponseKey, when non-empty, means the backend nests the item array one level
	// deeper: {"response": {"<ResponseKey>": [...]}} instead of {"response": [...]}.
	ResponseKey string
}

type ListResponse struct {
	Items  []json.RawMessage
	Total  int
	Cursor string
}
