package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestQueryPostureFramework(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"response":[{"name":"C-0016","severity":"High","status":"failed","scoreFactor":9,"noise":1}],"total":{"value":3}}`)
	})
	defer closeFn()

	out, err := s.queryPosture(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryPostureInput{Framework: "cis-v1.10.0", Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath[len(gotPath)-len("/posture/controls"):] != "/posture/controls" {
		t.Errorf("path = %q", gotPath)
	}
	filters := gotBody["innerFilters"].([]any)
	if filters[0].(map[string]any)["frameworkName"] != "cis-v1.10.0" {
		t.Errorf("innerFilters = %v", gotBody["innerFilters"])
	}
	if out.Total != 3 || out.Items[0]["name"] != "C-0016" {
		t.Errorf("out = %+v", out)
	}
	if _, dropped := out.Items[0]["noise"]; dropped == true {
		t.Errorf("summary should drop noise field")
	}
}
