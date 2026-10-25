package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestQueryRisksSeverityFilter(t *testing.T) {
	var gotBody map[string]any
	var gotPath string
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"response":[{"securityRiskID":"R-1","securityRiskName":"Public workload","severity":"Critical","category":"Exposure","noise":1}],"total":{"value":18}}`)
	})
	defer closeFn()

	out, err := s.queryRisks(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryRisksInput{Severity: "Critical", Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath[len(gotPath)-len("/securityrisks/list"):] != "/securityrisks/list" {
		t.Errorf("path = %q", gotPath)
	}
	filters := gotBody["innerFilters"].([]any)
	if filters[0].(map[string]any)["severity"] != "Critical" {
		t.Errorf("innerFilters = %v", gotBody["innerFilters"])
	}
	if out.Total != 18 || out.Items[0]["securityRiskName"] != "Public workload" {
		t.Errorf("out = %+v", out)
	}
	if _, dropped := out.Items[0]["noise"]; dropped {
		t.Errorf("summary should drop 'noise'")
	}
}
