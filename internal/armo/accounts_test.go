package armo

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountsSendsBearerAndDecodesNames(t *testing.T) {
	var gotPath, gotAuth, gotMethod, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotMethod, gotQuery = r.URL.Path, r.Header.Get("Authorization"), r.Method, r.URL.RawQuery
		_, _ = io.WriteString(w, `[{"customerName":"Acme","customerGUID":"g-1"},{"customerName":"Globex","customerGUID":"g-2"}]`)
	}))
	defer srv.Close()

	got, err := New(srv.URL, srv.Client()).Accounts(context.Background(), "tok")
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if gotMethod != http.MethodGet || !strings.HasSuffix(gotPath, "/api/v1/openid_customers") {
		t.Errorf("request = %s %s, want GET .../api/v1/openid_customers", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", gotAuth)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want none: the endpoint lists every account", gotQuery)
	}
	if len(got) != 2 || got[0] != (Account{GUID: "g-1", Name: "Acme"}) || got[1].Name != "Globex" {
		t.Errorf("accounts = %+v", got)
	}
}

func TestAccountsRequiresBearer(t *testing.T) {
	if _, err := New("http://unused", nil).Accounts(context.Background(), ""); err == nil {
		t.Fatal("expected an error without a bearer token")
	}
}

func TestAccountsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, err := New(srv.URL, srv.Client()).Accounts(context.Background(), "tok"); err == nil {
		t.Fatal("expected an error on 401")
	}
}

// Name lookups depend on Frontegg; their failures must not open the breaker
// that guards every tenant's data calls.
func TestAccountsFailuresDoNotTripBreaker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/openid_customers") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"response":[],"total":{"value":0}}`)
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client())
	for i := 0; i < 10; i++ {
		_, _ = c.Accounts(context.Background(), "tok")
	}
	if _, err := c.List(context.Background(), Identity{CustomerGUID: "g", APIKey: "k"}, ListRequest{Path: "/x"}); err != nil {
		t.Fatalf("List after failed name lookups: %v", err)
	}
}
