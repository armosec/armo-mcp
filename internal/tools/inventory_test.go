package tools

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestListInventorySummary(t *testing.T) {
	var gotPath string
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"response":[{"workloadName":"api","namespace":"prod","kind":"Deployment","resourceHash":"abc","noise":1}],"total":{"value":329}}`)
	})
	defer closeFn()

	out, err := s.listInventory(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, ListInventoryInput{Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath[len(gotPath)-len("/inventory/list"):] != "/inventory/list" {
		t.Errorf("path = %q", gotPath)
	}
	if out.Total != 329 || out.Items[0]["workloadName"] != "api" {
		t.Errorf("out = %+v", out)
	}
	if _, dropped := out.Items[0]["resourceHash"]; dropped {
		t.Errorf("summary should drop 'resourceHash' (not in summary set)")
	}
}
