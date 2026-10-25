package tools

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestQueryImagesSummary(t *testing.T) {
	var gotPath string
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"response":[{"repository":"nginx","tag":"1.25","criticalCount":3,"digest":"sha256:x","noise":1}],"total":{"value":70}}`)
	})
	defer closeFn()

	out, err := s.queryImages(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryImagesInput{Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath[len(gotPath)-len("/vulnerability_v2/image/list"):] != "/vulnerability_v2/image/list" {
		t.Errorf("path = %q", gotPath)
	}
	if out.Total != 70 || out.Items[0]["repository"] != "nginx" {
		t.Errorf("out = %+v", out)
	}
	if _, dropped := out.Items[0]["noise"]; dropped {
		t.Errorf("summary should drop unlisted 'noise' field")
	}
	if _, dropped := out.Items[0]["digest"]; dropped {
		t.Errorf("summary should drop 'digest' (not in summary set)")
	}
}
