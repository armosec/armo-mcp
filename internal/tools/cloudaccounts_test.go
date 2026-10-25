package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestListCloudAccountsProviderFilter(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"response":[{"accountName":"prod-aws","provider":"aws","isConnected":true,"criticalSeverityResources":5,"reportGUID":"x","noise":1}],"total":{"value":13}}`)
	})
	defer closeFn()

	out, err := s.listCloudAccounts(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, ListCloudAccountsInput{Provider: "AWS", Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath[len(gotPath)-len("/cloudposture/accounts"):] != "/cloudposture/accounts" {
		t.Errorf("path = %q", gotPath)
	}
	// provider is lowercased before sending
	filters := gotBody["innerFilters"].([]any)
	if filters[0].(map[string]any)["provider"] != "aws" {
		t.Errorf("expected lowercased provider=aws, got %v", gotBody["innerFilters"])
	}
	if out.Total != 13 || out.Items[0]["accountName"] != "prod-aws" {
		t.Errorf("out = %+v", out)
	}
	if _, dropped := out.Items[0]["noise"]; dropped {
		t.Errorf("summary should drop 'noise'")
	}
}
