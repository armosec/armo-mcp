package tools

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestQueryCloudComplianceSummary(t *testing.T) {
	var gotPath string
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"response":[{"name":"cis_1.4","complianceScorev1":72,"failedControls":40,"totalControls":140,"typeTags":["cis"],"reportGUID":"x","noise":1}],"total":{"value":14}}`)
	})
	defer closeFn()

	out, err := s.queryCloudCompliance(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryCloudComplianceInput{Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath[len(gotPath)-len("/cloudposture/frameworks"):] != "/cloudposture/frameworks" {
		t.Errorf("path = %q", gotPath)
	}
	if out.Total != 14 || out.Items[0]["name"] != "cis_1.4" {
		t.Errorf("out = %+v", out)
	}
	if _, dropped := out.Items[0]["reportGUID"]; dropped {
		t.Errorf("summary should drop 'reportGUID' (not in summary set)")
	}
}
