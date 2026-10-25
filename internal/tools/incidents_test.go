package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/armosec/armo-mcp/internal/armo"
)

func TestQueryIncidentsSeverityFilter(t *testing.T) {
	var gotBody map[string]any
	s, closeFn := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"response":[{"name":"inc-1","kind":"exec","clusterName":"prod","secret":"x","attributes":{"incidentStatus":"open","noise":"drop-me"}}],"total":{"value":2}}`)
	})
	defer closeFn()

	out, err := s.queryIncidents(context.Background(), armo.Identity{CustomerGUID: "g", APIKey: "k"}, QueryIncidentsInput{Severity: "High", Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Verified against live cadashboardbe: /runtime/incidents filters on "incidentSeverity"
	// via innerFilters (a flat "severity" key is silently ignored).
	filters, ok := gotBody["innerFilters"].([]any)
	if !ok || len(filters) != 1 {
		t.Fatalf("expected one innerFilters entry, body = %v", gotBody)
	}
	if filters[0].(map[string]any)["incidentSeverity"] != "High" {
		t.Errorf("expected innerFilters incidentSeverity=High, got %v", gotBody["innerFilters"])
	}
	if _, hasFlat := gotBody["severity"]; hasFlat {
		t.Errorf("incidents must not send a flat severity key, body = %v", gotBody)
	}
	if out.Items[0]["name"] != "inc-1" {
		t.Errorf("out = %+v", out)
	}
	if _, dropped := out.Items[0]["secret"]; dropped {
		t.Errorf("summary should drop unlisted 'secret' field")
	}
	// dotted-path projection: attributes.incidentStatus should survive
	attrs, ok := out.Items[0]["attributes"].(map[string]any)
	if !ok {
		t.Errorf("expected attributes to be map[string]any, got %T", out.Items[0]["attributes"])
	}
	if attrs["incidentStatus"] != "open" {
		t.Errorf("expected attributes.incidentStatus=open, got %v", attrs["incidentStatus"])
	}
	if _, hasNoise := attrs["noise"]; hasNoise {
		t.Errorf("attributes should not contain unlisted 'noise' field")
	}
}
