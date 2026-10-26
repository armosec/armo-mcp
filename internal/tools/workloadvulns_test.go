package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestQueryWorkloadVulnerabilitiesFlattensPerWorkload(t *testing.T) {
	var mu sync.Mutex
	var wlBody map[string]any
	cveBodies := map[string]map[string]any{}
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/vulnerability_v2/workload/list"):
			wlBody = body
			_, _ = io.WriteString(w, `{"response":[
				{"cluster":"c1","namespace":"ns1","kind":"deployment","name":"web"},
				{"cluster":"c1","namespace":"ns2","kind":"deployment","name":"empty"}],"total":{"value":7}}`)
		case strings.HasSuffix(r.URL.Path, "/vulnerability_v2/vulnerability/list"):
			f := body["innerFilters"].([]any)[0].(map[string]any)
			cveBodies[f["workload"].(string)] = f
			if f["workload"] == "web" {
				// CVE-1 twice (two packages): one row. cvssInfo must be projected away.
				_, _ = io.WriteString(w, `{"response":[
					{"name":"CVE-1","severity":"High","exploitable":"Known Exploited","isRelevant":"Yes","epssInfo":{"epss":0.9,"percentile":1},"cvssInfo":{"n":1}},
					{"name":"CVE-1","severity":"High","exploitable":"Known Exploited","isRelevant":"Yes"},
					{"name":"CVE-2","severity":"Low"}],"total":{"value":3}}`)
				return
			}
			_, _ = io.WriteString(w, `{"response":[],"total":{"value":0}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	defer closeFn()

	yes := true
	out, err := s.queryWorkloadVulnerabilities(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"},
		QueryWorkloadVulnInput{Cluster: "c1", Kind: "Deployment", InUse: &yes, Exploitable: &yes, Page: 2, PageSize: 50})
	if err != nil {
		t.Fatal(err)
	}
	// workload list: cluster and lowercased kind filters, page 2 (0-based 1), size clamped to the max
	wf := wlBody["innerFilters"].([]any)[0].(map[string]any)
	if wf["cluster"] != "c1" || wf["kind"] != "deployment" || len(wf) != 2 {
		t.Errorf("workload filter = %v", wf)
	}
	if wlBody["pageNum"] != float64(1) || wlBody["pageSize"] != float64(workloadVulnsMaxPageSize) {
		t.Errorf("paging = %v / %v", wlBody["pageNum"], wlBody["pageSize"])
	}
	// each workload gets its own scoped CVE call with the CVE filters
	web := cveBodies["web"]
	if web["namespace"] != "ns1" || web["cluster"] != "c1" || web["isRelevant"] != "Yes" || web["exploitable"] != "Known Exploited,High Likelihood" {
		t.Errorf("cve filter for web = %v", web)
	}
	if _, ok := cveBodies["empty"]; !ok {
		t.Errorf("workload without CVEs was not queried")
	}
	// total counts workloads; rows are flattened and deduplicated
	if out.Total != 7 || out.Page != 2 || out.Count != 2 {
		t.Fatalf("meta = %+v", out)
	}
	row := out.Items[0]
	if row["workload"] != "web" || row["namespace"] != "ns1" || row["kind"] != "deployment" || row["cluster"] != "c1" || row["name"] != "CVE-1" {
		t.Errorf("row = %+v", row)
	}
	if _, dropped := row["cvssInfo"]; dropped {
		t.Errorf("summary projection should drop cvssInfo: %+v", row)
	}
	if !strings.Contains(out.Note, "1 of them have no matching CVEs") {
		t.Errorf("note = %q", out.Note)
	}
}

func TestQueryWorkloadVulnerabilitiesFlagsTruncation(t *testing.T) {
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/workload/list") {
			_, _ = io.WriteString(w, `{"response":[{"cluster":"c","namespace":"n","kind":"deployment","name":"big"}],"total":{"value":1}}`)
			return
		}
		_, _ = io.WriteString(w, `{"response":[{"name":"CVE-1"}],"total":{"value":5000}}`)
	})
	defer closeFn()
	out, err := s.queryWorkloadVulnerabilities(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryWorkloadVulnInput{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Note, "only the first 100 are shown") {
		t.Errorf("note = %q", out.Note)
	}
}

func TestQueryWorkloadVulnerabilitiesBackendErrorFailsTheCall(t *testing.T) {
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/workload/list") {
			_, _ = io.WriteString(w, `{"response":[{"cluster":"c","namespace":"n","kind":"deployment","name":"w"}],"total":{"value":1}}`)
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer closeFn()
	if _, err := s.queryWorkloadVulnerabilities(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryWorkloadVulnInput{}); err == nil {
		t.Fatal("a failed CVE call must fail the page, not return a silently short one")
	}
}
