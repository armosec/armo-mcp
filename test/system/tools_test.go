//go:build systemtest

package system

import (
	"testing"
)

// TestAllToolsReturnValidEnvelope calls every tool read-only with a tiny page
// and asserts a well-formed response envelope. It asserts SHAPE, not counts:
// a tool legitimately returning zero items for the test tenant still passes,
// but is logged so an empty domain is visible, never silently treated as covered.
func TestAllToolsReturnValidEnvelope(t *testing.T) {
	cfg := loadConfig(t)
	s := connect(t, cfg.Endpoint, twoHeaderRT(cfg.Key, cfg.GUID))

	for _, name := range wantTools {
		name := name
		t.Run(name, func(t *testing.T) {
			args := map[string]any{"page": 1, "page_size": 2}
			if name == "list_accounts" {
				args = map[string]any{} // takes no parameters
			}
			res := callTool(t, s, name, args)
			if res.IsError {
				t.Fatalf("%s returned tool error: %+v", name, res.Content)
			}
			sc, ok := res.StructuredContent.(map[string]any)
			if !ok {
				t.Fatalf("%s: StructuredContent is %T, want map", name, res.StructuredContent)
			}
			if _, ok := sc["total"].(float64); !ok {
				t.Fatalf("%s: envelope missing numeric 'total'; got %+v", name, sc)
			}
			items, ok := sc["items"].([]any)
			if !ok {
				t.Fatalf("%s: envelope 'items' is %T, want array", name, sc["items"])
			}
			if len(items) == 0 {
				t.Logf("%s: 0 items for the test tenant (shape OK, data-empty)", name)
			}
		})
	}
}

// TestFieldSelectionProjects verifies the `fields` projection narrows returned
// item keys. Uses query_vulnerabilities, which the test tenant is expected to
// have data for.
func TestFieldSelectionProjects(t *testing.T) {
	cfg := loadConfig(t)
	s := connect(t, cfg.Endpoint, twoHeaderRT(cfg.Key, cfg.GUID))

	res := callTool(t, s, "query_vulnerabilities", map[string]any{
		"page": 1, "page_size": 1, "fields": []any{"name"},
	})
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	sc, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("StructuredContent is %T, want map", res.StructuredContent)
	}
	items, _ := sc["items"].([]any)
	if len(items) == 0 {
		t.Skip("no vulnerabilities for test tenant; cannot assert projection")
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("item is %T, want map", items[0])
	}
	if _, ok := item["name"]; !ok {
		t.Fatalf("projected item missing requested field 'name': %+v", item)
	}
	// severity is part of the summary projection but was NOT requested — its
	// presence would mean the fields param failed to narrow the response.
	if _, ok := item["severity"]; ok {
		t.Fatalf("projected item still has unrequested field 'severity' (fields param did not narrow): %+v", item)
	}
}
