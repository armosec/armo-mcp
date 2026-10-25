//go:build systemtest

package system

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestConnectivityListsAllTools is the black-box health/contract check: a
// successful MCP connect + ListTools that advertises exactly the 12 read-only
// tools. (Public route exposes only /mcp; /healthz is not ingress-routed.)
func TestConnectivityListsAllTools(t *testing.T) {
	cfg := loadConfig(t)
	s := connect(t, cfg.Endpoint, twoHeaderRT(cfg.Key, cfg.GUID))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lt, err := s.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	got := make([]string, 0, len(lt.Tools))
	for _, tool := range lt.Tools {
		got = append(got, tool.Name)
	}
	sort.Strings(got)
	want := append([]string(nil), wantTools...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("tool count = %d, want %d\n got=%v\nwant=%v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tool set mismatch at %d: got %q want %q\nfull got=%v", i, got[i], want[i], got)
		}
	}
}
