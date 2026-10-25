package tools

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestListRepositoriesSummary(t *testing.T) {
	var gotPath string
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"response":[{"name":"my-repo","kind":"Repository","statusText":"Scanned","reportGUID":"rg-1","designators":{"x":1}}],"total":{"value":1}}`)
	})
	defer closeFn()

	out, err := s.listRepositories(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, ListRepositoriesInput{Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath[len(gotPath)-len("/repositoryPosture/repositories"):] != "/repositoryPosture/repositories" {
		t.Errorf("path = %q", gotPath)
	}
	if out.Total != 1 || out.Items[0]["name"] != "my-repo" {
		t.Errorf("out = %+v", out)
	}
	if _, dropped := out.Items[0]["designators"]; dropped {
		t.Errorf("summary should drop 'designators' (not in summary set)")
	}
}
