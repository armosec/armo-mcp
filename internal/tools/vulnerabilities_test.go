package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/config"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*Server, func()) {
	t.Helper()
	backend := httptest.NewServer(handler)
	s := &Server{
		// Pass the full URL (with http:// scheme) — internal/armo's resolveURL
		// defaults bare hosts to https (see commit f1346b2, "drop scheme
		// heuristic"), which would break this plain-HTTP test server.
		Client: armo.New(backend.URL, backend.Client()),
		Cfg:    config.Config{DefaultPageSize: 25, MaxPageSize: 100},
	}
	return s, backend.Close
}

func TestQueryVulnerabilitiesSummaryProjection(t *testing.T) {
	var gotBody map[string]any
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"response":[{"name":"CVE-1","severity":"Critical","id":"x","cvssInfo":{"noise":1},"epssInfo":{"epss":0.5,"percentile":0.9},"workloadsCount":3}],"total":{"value":7}}`)
	})
	defer closeFn()

	out, err := s.queryVulnerabilities(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryVulnInput{Severity: "Critical", Page: 1, PageSize: 25})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.Total != 7 || out.Page != 1 || out.PageSize != 25 || out.Count != 1 {
		t.Errorf("meta = %+v", out)
	}
	// severity filter sent via innerFilters
	filters := gotBody["innerFilters"].([]any)
	if filters[0].(map[string]any)["severity"] != "Critical" {
		t.Errorf("innerFilters = %v", gotBody["innerFilters"])
	}
	// summary projection dropped cvssInfo but kept name/severity/id
	item := out.Items[0]
	if _, dropped := item["cvssInfo"]; dropped {
		t.Errorf("summary should drop cvssInfo, got %+v", item)
	}
	if item["name"] != "CVE-1" || item["severity"] != "Critical" {
		t.Errorf("summary item = %+v", item)
	}
	// dotted path keeps the nested epss only, and the workload count survives
	epss, _ := item["epssInfo"].(map[string]any)
	if epss["epss"] != 0.5 {
		t.Errorf("epssInfo.epss missing from summary: %+v", item)
	}
	if _, extra := epss["percentile"]; extra {
		t.Errorf("summary should keep only epssInfo.epss, got %+v", epss)
	}
	if item["workloadsCount"] != float64(3) {
		t.Errorf("workloadsCount = %v", item["workloadsCount"])
	}
}

func TestQueryVulnerabilitiesFullReturnsEverything(t *testing.T) {
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"response":[{"name":"CVE-1","cvssInfo":{"score":9}}],"total":{"value":1}}`)
	})
	defer closeFn()
	out, err := s.queryVulnerabilities(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryVulnInput{Full: true, Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Items[0]["cvssInfo"]; !ok {
		t.Errorf("full mode should keep cvssInfo, got %+v", out.Items[0])
	}
}

func TestQueryVulnerabilitiesWorkloadScopeFilters(t *testing.T) {
	var gotBody map[string]any
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"response":[],"total":{"value":0}}`)
	})
	defer closeFn()

	yes, no := true, false
	_, err := s.queryVulnerabilities(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryVulnInput{
		Cluster: "c1", Namespace: "ns", Workload: "web", Kind: "Deployment", CVE: "CVE-1", InUse: &yes, Exploitable: &no,
	})
	if err != nil {
		t.Fatal(err)
	}
	filters := gotBody["innerFilters"].([]any)
	if len(filters) != 1 {
		t.Fatalf("want one ANDed filter entry, got %v", filters)
	}
	want := map[string]any{"cluster": "c1", "namespace": "ns", "workload": "web", "kind": "deployment", "name": "CVE-1", "isRelevant": "Yes", "exploitable": "No"}
	got := filters[0].(map[string]any)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("filter %s = %v, want %v", k, got[k], v)
		}
	}
}

func TestVulnFilterExploitableTrueSendsBothLabels(t *testing.T) {
	yes := true
	if got := vulnFilter(QueryVulnInput{Exploitable: &yes})["exploitable"]; got != "Known Exploited,High Likelihood" {
		t.Errorf("exploitable=true sent %v", got)
	}
}

func TestQueryVulnerabilitiesNoFiltersSendsNone(t *testing.T) {
	var gotBody map[string]any
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"response":[],"total":{"value":0}}`)
	})
	defer closeFn()
	if _, err := s.queryVulnerabilities(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryVulnInput{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotBody["innerFilters"]; ok {
		t.Errorf("no filters expected, got %v", gotBody["innerFilters"])
	}
}
