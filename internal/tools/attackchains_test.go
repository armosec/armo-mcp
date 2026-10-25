package tools

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestQueryAttackChainsNestedEnvelope(t *testing.T) {
	var gotPath string
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		// nested envelope: response.attackChains
		_, _ = io.WriteString(w, `{"response":{"attackChains":[{"name":"chain-1","guid":"g1","clusterName":"prod","attackChainNodes":{"big":"drop"}}]},"total":{"value":28}}`)
	})
	defer closeFn()

	out, err := s.queryAttackChains(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryAttackChainsInput{Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath[len(gotPath)-len("/attackchains"):] != "/attackchains" {
		t.Errorf("path = %q", gotPath)
	}
	if out.Total != 28 || len(out.Items) != 1 || out.Items[0]["name"] != "chain-1" {
		t.Errorf("nested envelope not decoded: out = %+v", out)
	}
	if _, dropped := out.Items[0]["attackChainNodes"]; dropped {
		t.Errorf("summary should drop bulky 'attackChainNodes'")
	}
}
