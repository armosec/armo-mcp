package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/config"
)

const cloudControlsResp = `{"response":[{"cloudControlName":"S3 public","cloudControlID":"C-1","frameworkName":"cis_1.4","severity":"critical","status":"failed","complianceScore":40,"remediation":"long...","noise":1}],"total":{"value":117974}}`

// TestQueryCloudPostureAutoScopesToLatestReports verifies that, with no explicit
// report_guid, the tool first resolves every cloud account's reportGUID and
// scopes the controls query to them (the only filter the backend serves
// efficiently), combined with severity/framework in one innerFilters object.
func TestQueryCloudPostureAutoScopesToLatestReports(t *testing.T) {
	var controlsBody map[string]any
	var accountsHit, controlsHit int
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/cloudposture/accounts"):
			accountsHit++
			_, _ = io.WriteString(w, `{"response":[{"cloudAccountGUID":"a1","reportGUID":"r1"},{"cloudAccountGUID":"a2","reportGUID":"r2"},{"cloudAccountGUID":"a3","reportGUID":"r1"}],"total":{"value":3}}`)
		case strings.HasSuffix(r.URL.Path, "/cloudposture/controls"):
			controlsHit++
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &controlsBody)
			_, _ = io.WriteString(w, cloudControlsResp)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})
	defer closeFn()

	out, err := s.queryCloudPosture(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"},
		QueryCloudPostureInput{Severity: "Critical", Framework: "cis_1.4", Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if accountsHit != 1 || controlsHit != 1 {
		t.Fatalf("expected 1 accounts + 1 controls call, got %d/%d", accountsHit, controlsHit)
	}
	filters := controlsBody["innerFilters"].([]any)
	if len(filters) != 1 {
		t.Fatalf("expected one combined innerFilters object, got %v", controlsBody["innerFilters"])
	}
	f := filters[0].(map[string]any)
	// reportGUID scope = deduped, latest-per-account, comma-joined in stable order.
	if f["reportGUID"] != "r1,r2" {
		t.Errorf("reportGUID scope = %v, want r1,r2", f["reportGUID"])
	}
	// severity lowercased; severity + frameworkName combined into the same object.
	if f["severity"] != "critical" || f["frameworkName"] != "cis_1.4" {
		t.Errorf("filter = %v (want severity=critical, frameworkName=cis_1.4)", f)
	}
	if out.Total != 117974 || out.Items[0]["cloudControlName"] != "S3 public" {
		t.Errorf("out = %+v", out)
	}
	if _, dropped := out.Items[0]["remediation"]; dropped {
		t.Errorf("summary should drop bulky 'remediation'")
	}
}

// TestQueryCloudPostureExplicitReportGUID verifies an explicit report_guid is
// used verbatim and skips the accounts lookup entirely.
func TestQueryCloudPostureExplicitReportGUID(t *testing.T) {
	var controlsBody map[string]any
	var accountsHit int
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cloudposture/accounts") {
			accountsHit++
		}
		if strings.HasSuffix(r.URL.Path, "/cloudposture/controls") {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &controlsBody)
		}
		_, _ = io.WriteString(w, cloudControlsResp)
	})
	defer closeFn()

	if _, err := s.queryCloudPosture(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"},
		QueryCloudPostureInput{ReportGUID: "rX,rY"}); err != nil {
		t.Fatal(err)
	}
	if accountsHit != 0 {
		t.Errorf("explicit report_guid must not trigger an accounts lookup (got %d)", accountsHit)
	}
	f := controlsBody["innerFilters"].([]any)[0].(map[string]any)
	if f["reportGUID"] != "rX,rY" {
		t.Errorf("reportGUID = %v, want rX,rY", f["reportGUID"])
	}
}

// TestQueryCloudPosturePaginatesAccounts verifies that when the tenant has more
// cloud accounts than fit on one page, latestCloudReportGUIDs pages through all
// of them rather than silently dropping accounts past the first page.
func TestQueryCloudPosturePaginatesAccounts(t *testing.T) {
	var controlsBody map[string]any
	var accountsHits []int
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var reqBody map[string]any
		_ = json.Unmarshal(b, &reqBody)
		switch {
		case strings.HasSuffix(r.URL.Path, "/cloudposture/accounts"):
			pageNum, _ := reqBody["pageNum"].(float64)
			accountsHits = append(accountsHits, int(pageNum))
			switch int(pageNum) { // the backend's pageNum is 1-based
			case 1:
				_, _ = io.WriteString(w, `{"response":[{"cloudAccountGUID":"a1","reportGUID":"r1"},{"cloudAccountGUID":"a2","reportGUID":"r2"}],"total":{"value":3}}`)
			case 2:
				_, _ = io.WriteString(w, `{"response":[{"cloudAccountGUID":"a3","reportGUID":"r3"}],"total":{"value":3}}`)
			default:
				t.Errorf("unexpected accounts pageNum %v", pageNum)
			}
		case strings.HasSuffix(r.URL.Path, "/cloudposture/controls"):
			controlsBody = reqBody
			_, _ = io.WriteString(w, cloudControlsResp)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})
	defer closeFn()

	out, err := s.queryCloudPosture(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"},
		QueryCloudPostureInput{Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(accountsHits) != 2 {
		t.Fatalf("expected 2 accounts page fetches, got %d (%v)", len(accountsHits), accountsHits)
	}
	f := controlsBody["innerFilters"].([]any)[0].(map[string]any)
	if f["reportGUID"] != "r1,r2,r3" {
		t.Errorf("reportGUID scope = %v, want r1,r2,r3 (pagination should collect every account)", f["reportGUID"])
	}
	if out.Total != 117974 {
		t.Errorf("out = %+v", out)
	}
}

// TestQueryCloudPosturePaginatesWhenTotalOmitted verifies pagination does not
// rely on Total: when the accounts envelope omits "total" (so armo.Client leaves
// Total=0) and the first page is FULL, the tool must keep paging to a short page
// rather than stopping after page 0. MaxPageSize is set to 2 so a full page is 2.
func TestQueryCloudPosturePaginatesWhenTotalOmitted(t *testing.T) {
	var accountsPages []int
	var controlsBody map[string]any
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var reqBody map[string]any
		_ = json.Unmarshal(b, &reqBody)
		switch {
		case strings.HasSuffix(r.URL.Path, "/cloudposture/accounts"):
			pageNum, _ := reqBody["pageNum"].(float64)
			accountsPages = append(accountsPages, int(pageNum))
			switch int(pageNum) { // the backend's pageNum is 1-based
			case 1: // full page (== pageSize 2), and NO "total" field
				_, _ = io.WriteString(w, `{"response":[{"reportGUID":"r1"},{"reportGUID":"r2"}]}`)
			case 2: // short page -> last page
				_, _ = io.WriteString(w, `{"response":[{"reportGUID":"r3"}]}`)
			default:
				t.Errorf("unexpected accounts pageNum %v", pageNum)
			}
		case strings.HasSuffix(r.URL.Path, "/cloudposture/controls"):
			controlsBody = reqBody
			_, _ = io.WriteString(w, cloudControlsResp)
		}
	}))
	defer backend.Close()

	s := &Server{
		Client: armo.New(backend.URL, backend.Client()),
		Cfg:    config.Config{DefaultPageSize: 25, MaxPageSize: 2},
	}
	if _, err := s.queryCloudPosture(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"},
		QueryCloudPostureInput{}); err != nil {
		t.Fatal(err)
	}
	if len(accountsPages) != 2 {
		t.Fatalf("expected 2 account page fetches (Total omitted + full first page), got %v", accountsPages)
	}
	f := controlsBody["innerFilters"].([]any)[0].(map[string]any)
	if f["reportGUID"] != "r1,r2,r3" {
		t.Errorf("reportGUID scope = %v, want r1,r2,r3", f["reportGUID"])
	}
}

// TestQueryCloudPostureNoAccounts verifies that when no cloud accounts (thus no
// report scope) exist, the tool returns an empty result without ever issuing
// the unbounded controls query.
func TestQueryCloudPostureNoAccounts(t *testing.T) {
	var controlsHit int
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cloudposture/controls") {
			controlsHit++
		}
		_, _ = io.WriteString(w, `{"response":[],"total":{"value":0}}`)
	})
	defer closeFn()

	out, err := s.queryCloudPosture(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"},
		QueryCloudPostureInput{})
	if err != nil {
		t.Fatal(err)
	}
	if controlsHit != 0 {
		t.Errorf("controls query must not run when there is no report scope (got %d)", controlsHit)
	}
	if out.Total != 0 || out.Count != 0 {
		t.Errorf("out = %+v, want empty", out)
	}
}
