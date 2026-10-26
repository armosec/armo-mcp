package armo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestListBuildsRequestAndDecodesEnvelope(t *testing.T) {
	var gotPath, gotAPIKey, gotGUID string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("x-api-key")
		gotGUID = r.URL.Query().Get("customerGUID")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(w, `{"response":[{"name":"CVE-1"},{"name":"CVE-2"}],"total":{"value":42},"cursor":"c1"}`)
	}))
	defer srv.Close()

	// srv.URL is like http://127.0.0.1:PORT — pass full URL with scheme.
	c := New(srv.URL, srv.Client())

	resp, err := c.List(context.Background(), Identity{CustomerGUID: "guid-1", APIKey: "key-1"}, ListRequest{
		Path:         "/vulnerability_v2/vulnerability/list",
		PageNum:      0,
		PageSize:     25,
		InnerFilters: []map[string]any{{"severity": "Critical"}},
	})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if !strings.HasSuffix(gotPath, "/api/v1/vulnerability_v2/vulnerability/list") {
		t.Errorf("path = %q, want .../api/v1/vulnerability_v2/vulnerability/list", gotPath)
	}
	if gotAPIKey != "key-1" {
		t.Errorf("x-api-key = %q, want key-1", gotAPIKey)
	}
	if gotGUID != "guid-1" {
		t.Errorf("customerGUID = %q, want guid-1", gotGUID)
	}
	// PageNum is 0-based here, the backend's is 1-based (it serves 0 and 1 as the same page).
	if gotBody["pageNum"].(float64) != 1 {
		t.Errorf("pageNum = %v, want 1 for PageNum 0", gotBody["pageNum"])
	}
	if gotBody["pageSize"].(float64) != 25 {
		t.Errorf("pageSize = %v, want 25", gotBody["pageSize"])
	}
	if len(resp.Items) != 2 || resp.Total != 42 || resp.Cursor != "c1" {
		t.Errorf("resp = %+v, want 2 items / total 42 / cursor c1", resp)
	}
	// Assert that innerFilters appears in the request body with expected severity.
	innerFilters, ok := gotBody["innerFilters"].([]any)
	if !ok || len(innerFilters) != 1 {
		t.Errorf("innerFilters = %v, want slice with 1 element", gotBody["innerFilters"])
	} else {
		filter := innerFilters[0].(map[string]any)
		if filter["severity"] != "Critical" {
			t.Errorf("innerFilters[0].severity = %v, want Critical", filter["severity"])
		}
	}
}

func TestListUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"nope"}`)
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client())
	_, err := c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "k"}, ListRequest{Path: "/x"})
	if err == nil || !strings.HasPrefix(err.Error(), "unauthorized") {
		t.Fatalf("err = %v, want prefix 'unauthorized'", err)
	}
}

func TestListExtraKeysAndGuarding(t *testing.T) {
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(w, `{"response":[]}`)
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())

	// Test that Extra flat keys are merged into body, but reserved keys are not overridden.
	resp, err := c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "k"}, ListRequest{
		Path:     "/test",
		PageNum:  0,
		PageSize: 25,
		Extra: map[string]any{
			"severity":  "high",
			"pageSize":  999, // Should be ignored; real pageSize is 25
			"customKey": "customValue",
		},
	})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}

	// Verify that severity is in the body (Extra flat key merged).
	if gotBody["severity"] != "high" {
		t.Errorf("severity = %v, want high", gotBody["severity"])
	}

	// Verify that customKey is in the body.
	if gotBody["customKey"] != "customValue" {
		t.Errorf("customKey = %v, want customValue", gotBody["customKey"])
	}

	// Verify that pageSize was NOT overridden by Extra and is still 25.
	if gotBody["pageSize"].(float64) != 25 {
		t.Errorf("pageSize = %v, want 25 (not overridden by Extra)", gotBody["pageSize"])
	}

	if resp == nil {
		t.Errorf("expected valid response")
	}
}

func TestListNestedResponseEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"response":{"attackChains":[{"name":"c1"},{"name":"c2"}]},"total":{"value":9}}`)
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client())
	resp, err := c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "k"},
		ListRequest{Path: "/attackchains", PageSize: 25, ResponseKey: "attackChains"})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(resp.Items) != 2 || resp.Total != 9 {
		t.Fatalf("got %d items / total %d, want 2 / 9", len(resp.Items), resp.Total)
	}
}

func TestListUnauthorized401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"invalid key"}`)
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client())
	_, err := c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "bad"}, ListRequest{Path: "/x"})
	if err == nil || !strings.HasPrefix(err.Error(), "unauthorized") {
		t.Fatalf("err = %v, want prefix 'unauthorized'", err)
	}
}

func TestListServerError500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"message":"internal error"}`)
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client())
	_, err := c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "k"}, ListRequest{Path: "/x"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v, want message containing '500'", err)
	}
}

func TestListCircuitOpensAfterFailures(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"message":"boom"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())

	// Drive enough consecutive failures to trip the breaker (configured for 5).
	for i := 0; i < 6; i++ {
		_, _ = c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "k"}, ListRequest{Path: "/x"})
	}

	hitsAfterTrip := atomic.LoadInt32(&hits)
	if hitsAfterTrip == 0 {
		t.Fatalf("expected server to have been hit at least once before breaker opened")
	}

	_, err := c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "k"}, ListRequest{Path: "/x"})
	if err == nil || !strings.HasPrefix(err.Error(), "backend unavailable") {
		t.Fatalf("err = %v, want prefix 'backend unavailable'", err)
	}

	if got := atomic.LoadInt32(&hits); got != hitsAfterTrip {
		t.Errorf("hits = %d after presumed-open call, want unchanged from %d (request should have been short-circuited)", got, hitsAfterTrip)
	}
}

// TestListCircuitStaysClosedOn4xx verifies that repeated 4xx client-request
// errors (e.g. 404) do NOT trip the breaker: a caller sending bad requests must
// not open the shared per-instance breaker for other tenants.
func TestListCircuitStaysClosedOn4xx(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"not found"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())

	// Far more consecutive 4xx than the breaker's trip threshold (5).
	for i := 0; i < 10; i++ {
		_, _ = c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "k"}, ListRequest{Path: "/x"})
	}
	before := atomic.LoadInt32(&hits)

	// The next call must still reach the server (breaker closed) and surface a
	// request error, not "backend unavailable".
	_, err := c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "k"}, ListRequest{Path: "/x"})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v, want message containing '404'", err)
	}
	if got := atomic.LoadInt32(&hits); got != before+1 {
		t.Errorf("hits = %d, want %d — the request should have reached the server (breaker must stay closed on 4xx)", got, before+1)
	}
}

// captureHeaders returns a test server plus a func that yields the headers of
// the last request it received.
func captureHeaders(t *testing.T) (*httptest.Server, func() http.Header) {
	t.Helper()
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Clone())
		_, _ = w.Write([]byte(`{"response":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header {
		h, _ := got.Load().(http.Header)
		return h
	}
}

func listAs(t *testing.T, srv *httptest.Server, ident Identity) {
	t.Helper()
	c := New(srv.URL, nil)
	if _, err := c.List(context.Background(), ident,
		ListRequest{Path: "/inventory/list", PageNum: 1, PageSize: 10}); err != nil {
		t.Fatalf("List: %v", err)
	}
}

func TestClientSendsBearerWhenSet(t *testing.T) {
	srv, headers := captureHeaders(t)
	listAs(t, srv, Identity{CustomerGUID: "tenant-a", Bearer: "tok-123"})

	h := headers()
	if got := h.Get("Authorization"); got != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want Bearer tok-123", got)
	}
	if vals, present := h["X-Api-Key"]; present {
		t.Errorf("x-api-key must not be sent alongside a bearer, got %q", vals)
	}
}

func TestClientSendsAPIKeyWhenNoBearer(t *testing.T) {
	srv, headers := captureHeaders(t)
	listAs(t, srv, Identity{CustomerGUID: "tenant-a", APIKey: "key-123"})

	h := headers()
	if got := h.Get("x-api-key"); got != "key-123" {
		t.Errorf("x-api-key = %q, want key-123", got)
	}
	if vals, present := h["Authorization"]; present {
		t.Errorf("Authorization must be absent on the API-key path, got %q", vals)
	}
}

// An identity that somehow holds both credentials must still put exactly one
// on the wire, and it must be the bearer.
func TestClientNeverSendsBothCredentials(t *testing.T) {
	srv, headers := captureHeaders(t)
	listAs(t, srv, Identity{CustomerGUID: "tenant-a", APIKey: "key-123", Bearer: "tok-123"})

	h := headers()
	_, hasKey := h["X-Api-Key"]
	_, hasAuth := h["Authorization"]
	if hasKey && hasAuth {
		t.Fatalf("both x-api-key and Authorization were sent: %v", h)
	}
	if hasKey || !hasAuth {
		t.Errorf("bearer must win when both are set; x-api-key present=%v Authorization present=%v", hasKey, hasAuth)
	}
}

func TestClientCustomerGUIDComesOnlyFromIdentity(t *testing.T) {
	var gotQuery map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte(`{"response":[]}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil)
	// A path that tries to smuggle its own customerGUID must not win.
	_, err := c.List(context.Background(),
		Identity{CustomerGUID: "tenant-a", Bearer: "tok"},
		ListRequest{Path: "/inventory/list?customerGUID=other", PageNum: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if v := gotQuery["customerGUID"]; len(v) != 1 || v[0] != "tenant-a" {
		t.Errorf("customerGUID = %v, want exactly [tenant-a]", v)
	}
}
