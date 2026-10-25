package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/auth"
	"github.com/armosec/armo-mcp/internal/cache"
	"github.com/armosec/armo-mcp/internal/config"
	"github.com/armosec/armo-mcp/internal/limit"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const accountsJSON = `[{"customerName":"Acme","customerGUID":"g-acme"},` +
	`{"customerName":"Globex","customerGUID":"g-globex"},` +
	`{"customerName":"Twin","customerGUID":"g-twin1"},{"customerName":"twin","customerGUID":"g-twin2"},` +
	`{"customerName":"Not In Token","customerGUID":"g-new"},` +
	// Same name as an account in the token, but added after sign-in.
	`{"customerName":"Globex","customerGUID":"g-new-globex"}]`

// accountsBackend fakes /openid_customers and records the customerGUID each
// list request was sent for.
func accountsBackend(t *testing.T, status int) (*httptest.Server, *atomic.Int64, *atomic.Value) {
	t.Helper()
	return accountsBackendWith(t, status, false)
}

// accountsBackendWith can stall /openid_customers until the request is cancelled.
func accountsBackendWith(t *testing.T, status int, stall bool) (*httptest.Server, *atomic.Int64, *atomic.Value) {
	t.Helper()
	var lookups atomic.Int64
	var lastGUID atomic.Value
	lastGUID.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/openid_customers") {
			lookups.Add(1)
			if stall {
				<-r.Context().Done()
				return
			}
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			_, _ = io.WriteString(w, accountsJSON)
			return
		}
		lastGUID.Store(r.URL.Query().Get("customerGUID"))
		_, _ = io.WriteString(w, `{"response":[],"total":{"value":0}}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &lookups, &lastGUID
}

func bearerIdentity() armo.Identity {
	return armo.Identity{
		CustomerGUID: "g-acme", Bearer: "tok",
		Tenants: []string{"g-acme", "g-globex", "g-twin1", "g-twin2"},
	}
}

// fixedIdentity resolves to one identity; unlike StaticAuthenticator it
// accepts an OAuth identity, which has no API key.
type fixedIdentity armo.Identity

func (f fixedIdentity) Resolve(http.Header) (armo.Identity, error) { return armo.Identity(f), nil }

var _ auth.Authenticator = fixedIdentity{}

func accountsServer(t *testing.T, srv *httptest.Server, ident armo.Identity) *Server {
	t.Helper()
	return &Server{
		Client:   armo.New(srv.URL, srv.Client()),
		Auth:     fixedIdentity(ident),
		Cfg:      config.Config{DefaultPageSize: 25, MaxPageSize: 100},
		Accounts: cache.New[[]armo.Account](time.Minute),
	}
}

func listCloudAccounts(t *testing.T, s *Server, account string) (QueryResult, error) {
	t.Helper()
	_, out, err := s.ListCloudAccounts(context.Background(), &mcp.CallToolRequest{},
		ListCloudAccountsInput{AccountInput: AccountInput{Account: account}})
	return out, err
}

func TestListAccountsReturnsNamesAndMarksActive(t *testing.T) {
	srv, _, _ := accountsBackend(t, http.StatusOK)
	s := accountsServer(t, srv, bearerIdentity())
	_, out, err := s.ListAccounts(context.Background(), &mcp.CallToolRequest{}, ListAccountsInput{})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	// g-new is in the account list but not the token's tenantIds: the backend
	// would reject it, so it is not offered.
	want := []map[string]any{
		{"customerGUID": "g-acme", "customerName": "Acme", "active": true},
		{"customerGUID": "g-globex", "customerName": "Globex", "active": false},
		{"customerGUID": "g-twin1", "customerName": "Twin", "active": false},
		{"customerGUID": "g-twin2", "customerName": "twin", "active": false},
	}
	got, _ := json.Marshal(out.Items)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Errorf("items = %s\nwant %s", got, exp)
	}
	if out.Total != 4 || out.Count != 4 {
		t.Errorf("total/count = %d/%d, want 4/4", out.Total, out.Count)
	}
	if out.Note != "" {
		t.Errorf("unexpected note: %q", out.Note)
	}
}

func TestListAccountsWithoutNamesWhenLookupFails(t *testing.T) {
	srv, _, _ := accountsBackend(t, http.StatusInternalServerError)
	s := accountsServer(t, srv, bearerIdentity())
	_, out, err := s.ListAccounts(context.Background(), &mcp.CallToolRequest{}, ListAccountsInput{})
	if err != nil {
		t.Fatalf("a failed name lookup should still list the token's accounts: %v", err)
	}
	if out.Count != 4 || out.Items[0]["customerGUID"] != "g-acme" {
		t.Errorf("items = %+v", out.Items)
	}
	if _, ok := out.Items[0]["customerName"]; ok {
		t.Errorf("no name should be invented: %+v", out.Items[0])
	}
	if out.Note == "" {
		t.Error("the result should say names could not be looked up")
	}
}

func TestListAccountsAPIKeyListsOnlyItsAccount(t *testing.T) {
	srv, lookups, _ := accountsBackend(t, http.StatusOK)
	s := accountsServer(t, srv, armo.Identity{CustomerGUID: "g-key", APIKey: "k"})
	_, out, err := s.ListAccounts(context.Background(), &mcp.CallToolRequest{}, ListAccountsInput{})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if out.Count != 1 || out.Items[0]["customerGUID"] != "g-key" || out.Items[0]["active"] != true {
		t.Errorf("items = %+v", out.Items)
	}
	if lookups.Load() != 0 {
		t.Error("an API key has no account list to look up")
	}
}

func TestToolResultNamesItsAccount(t *testing.T) {
	srv, _, guid := accountsBackend(t, http.StatusOK)
	s := accountsServer(t, srv, bearerIdentity())
	out, err := listCloudAccounts(t, s, "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out.Account == nil || *out.Account != (AccountRef{GUID: "g-acme", Name: "Acme"}) {
		t.Errorf("account = %+v, want g-acme/Acme", out.Account)
	}
	if guid.Load() != "g-acme" {
		t.Errorf("sent customerGUID = %v, want the active tenant", guid.Load())
	}
}

func TestToolSelectsAccount(t *testing.T) {
	cases := []struct{ name, account, wantGUID, wantName string }{
		{"by GUID", "g-globex", "g-globex", "Globex"},
		{"by GUID, other case", "G-GLOBEX", "g-globex", "Globex"},
		{"by name", "Globex", "g-globex", "Globex"},
		{"by name, other case and spaces", "  globex ", "g-globex", "Globex"},
		{"the active account by name", "acme", "g-acme", "Acme"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, guid := accountsBackend(t, http.StatusOK)
			s := accountsServer(t, srv, bearerIdentity())
			out, err := listCloudAccounts(t, s, tc.account)
			if err != nil {
				t.Fatalf("call: %v", err)
			}
			if guid.Load() != tc.wantGUID {
				t.Errorf("sent customerGUID = %v, want %s", guid.Load(), tc.wantGUID)
			}
			if out.Account == nil || *out.Account != (AccountRef{GUID: tc.wantGUID, Name: tc.wantName}) {
				t.Errorf("account = %+v", out.Account)
			}
		})
	}
}

func TestToolRejectsAccount(t *testing.T) {
	cases := []struct{ name, account, wantErr string }{
		{"unknown name", "Initech", "list_accounts"},
		{"GUID outside the token", "g-other", "list_accounts"},
		{"ambiguous name", "twin", "g-twin1"},
		// Listed by the backend but missing from the token: signing in again
		// would mint a token that lists it.
		{"account newer than the token", "Not In Token", "sign in again"},
		{"account newer than the token, by GUID", "g-new", "sign in again"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, guid := accountsBackend(t, http.StatusOK)
			s := accountsServer(t, srv, bearerIdentity())
			_, err := listCloudAccounts(t, s, tc.account)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
			if guid.Load() != "" {
				t.Errorf("a rejected selection must not reach the backend, sent %v", guid.Load())
			}
		})
	}
}

func TestToolSelectsByGUIDWhenNameLookupFails(t *testing.T) {
	srv, _, guid := accountsBackend(t, http.StatusInternalServerError)
	s := accountsServer(t, srv, bearerIdentity())
	out, err := listCloudAccounts(t, s, "g-globex")
	if err != nil {
		t.Fatalf("a GUID needs no name lookup: %v", err)
	}
	if guid.Load() != "g-globex" || out.Account == nil || out.Account.GUID != "g-globex" || out.Account.Name != "" {
		t.Errorf("sent %v, account = %+v", guid.Load(), out.Account)
	}
	_, err = listCloudAccounts(t, s, "Globex")
	if err == nil || !strings.Contains(err.Error(), "g-acme (active)") || !strings.Contains(err.Error(), "g-globex") {
		t.Errorf("without names, the error should offer the usable GUIDs; err = %v", err)
	}
}

func TestAPIKeyCannotSelectAnotherAccount(t *testing.T) {
	srv, _, guid := accountsBackend(t, http.StatusOK)
	s := accountsServer(t, srv, armo.Identity{CustomerGUID: "g-key", APIKey: "k"})
	if _, err := listCloudAccounts(t, s, "g-acme"); err == nil {
		t.Fatal("an API key is bound to one account")
	}
	out, err := listCloudAccounts(t, s, "g-key")
	if err != nil {
		t.Fatalf("naming its own account is fine: %v", err)
	}
	if guid.Load() != "g-key" || out.Account == nil || *out.Account != (AccountRef{GUID: "g-key"}) {
		t.Errorf("sent %v, account = %+v", guid.Load(), out.Account)
	}
}

func TestAccountNamesAreCachedPerToken(t *testing.T) {
	srv, lookups, _ := accountsBackend(t, http.StatusOK)
	s := accountsServer(t, srv, bearerIdentity())
	for i := 0; i < 3; i++ {
		if _, err := listCloudAccounts(t, s, "Globex"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if lookups.Load() != 1 {
		t.Errorf("name lookups = %d, want 1", lookups.Load())
	}
	other := bearerIdentity()
	other.Bearer = "another-token"
	s.Auth = fixedIdentity(other)
	if _, err := listCloudAccounts(t, s, ""); err != nil {
		t.Fatalf("call: %v", err)
	}
	if lookups.Load() != 2 {
		t.Errorf("a different token must not reuse the first token's list; lookups = %d", lookups.Load())
	}
}

// Every tool except list_accounts takes the account parameter.
func TestEveryToolAcceptsAccount(t *testing.T) {
	ctx := context.Background()
	m := mcp.NewServer(&mcp.Implementation{Name: "armo-mcp", Version: "test"}, nil)
	(&Server{}).Register(m)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := m.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = session.Close() }()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	seen := 0
	for _, tool := range res.Tools {
		b, _ := json.Marshal(tool.InputSchema)
		has := strings.Contains(string(b), `"account"`)
		if tool.Name == "list_accounts" {
			if has {
				t.Error("list_accounts must not take an account")
			}
			continue
		}
		seen++
		if !has {
			t.Errorf("%s has no account parameter: %s", tool.Name, b)
		}
	}
	if seen != 11 {
		t.Errorf("checked %d tools, want 11", seen)
	}
}

// A name shared by an account in the token and one added after sign-in picks
// the usable one rather than reporting ambiguity.
func TestToolNameIgnoresUnavailableDuplicate(t *testing.T) {
	srv, _, guid := accountsBackend(t, http.StatusOK)
	s := accountsServer(t, srv, bearerIdentity())
	if _, err := listCloudAccounts(t, s, "Globex"); err != nil {
		t.Fatalf("call: %v", err)
	}
	if guid.Load() != "g-globex" {
		t.Errorf("sent customerGUID = %v, want g-globex", guid.Load())
	}
}

// A failed lookup is remembered per token, so an outage costs one lookup per
// token rather than one per tool call.
func TestAccountLookupFailureBacksOff(t *testing.T) {
	srv, lookups, _ := accountsBackend(t, http.StatusInternalServerError)
	s := accountsServer(t, srv, bearerIdentity())
	for i := 0; i < 3; i++ {
		if _, err := listCloudAccounts(t, s, ""); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if lookups.Load() != 1 {
		t.Errorf("lookups = %d, want 1", lookups.Load())
	}
	orig := accountLookupBackoff
	accountLookupBackoff = 0
	t.Cleanup(func() { accountLookupBackoff = orig })
	other := bearerIdentity()
	other.Bearer = "another-token"
	s.Auth = fixedIdentity(other)
	if _, err := listCloudAccounts(t, s, ""); err != nil {
		t.Fatalf("call: %v", err)
	}
	if lookups.Load() != 2 {
		t.Errorf("another token is not covered by the first token's backoff; lookups = %d", lookups.Load())
	}
}

// A stalled lookup must not use up the deadline the data request needs.
func TestStalledAccountLookupLeavesTimeForData(t *testing.T) {
	orig := accountLookupTimeout
	accountLookupTimeout = 50 * time.Millisecond
	t.Cleanup(func() { accountLookupTimeout = orig })

	srv, _, guid := accountsBackendWith(t, http.StatusOK, true)
	s := accountsServer(t, srv, bearerIdentity())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, out, err := s.ListCloudAccounts(ctx, &mcp.CallToolRequest{}, ListCloudAccountsInput{})
	if err != nil {
		t.Fatalf("data call after a stalled lookup: %v", err)
	}
	if guid.Load() != "g-acme" || out.Account == nil || *out.Account != (AccountRef{GUID: "g-acme"}) {
		t.Errorf("sent %v, account = %+v", guid.Load(), out.Account)
	}
}

// Name lookups are labels, so a call the limiter rejects makes none.
func TestRateLimitedCallLooksUpNoNames(t *testing.T) {
	srv, lookups, _ := accountsBackend(t, http.StatusInternalServerError)
	s := accountsServer(t, srv, bearerIdentity())
	s.Limiter = limit.New(1, 1)
	if _, err := listCloudAccounts(t, s, ""); err != nil {
		t.Fatalf("first call: %v", err)
	}
	other := bearerIdentity()
	other.Bearer = "another-token"
	s.Auth = fixedIdentity(other)
	if _, err := listCloudAccounts(t, s, ""); err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("err = %v, want a rate-limit rejection", err)
	}
	if lookups.Load() != 1 {
		t.Errorf("lookups = %d, want 1: the rejected call must not look names up", lookups.Load())
	}
}

// A rejected selection logs why, never the caller's raw account input.
func TestAccountRejectionDoesNotLogInput(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	t.Cleanup(zap.ReplaceGlobals(zap.New(core)))
	srv, _, _ := accountsBackend(t, http.StatusOK)
	s := accountsServer(t, srv, bearerIdentity())
	const secret = "Initech merger target"
	if _, err := listCloudAccounts(t, s, secret); err == nil {
		t.Fatal("expected a rejection")
	}
	found := false
	for _, e := range logs.All() {
		if e.Message == "tool call rejected: account selection failed" {
			found = true
			if e.ContextMap()["reason"] != "unknown_account" {
				t.Errorf("reason = %v, want unknown_account", e.ContextMap()["reason"])
			}
		}
		if strings.Contains(fmt.Sprint(e.Message, e.ContextMap()), secret) {
			t.Errorf("log entry %q carries the raw account input", e.Message)
		}
	}
	if !found {
		t.Error("the rejection was not logged")
	}
}

// The name label is looked up alongside the data request, not before it.
func TestNameLookupOverlapsDataRequest(t *testing.T) {
	dataStarted := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/openid_customers") {
			select {
			case <-dataStarted:
			case <-time.After(2 * time.Second):
				w.WriteHeader(http.StatusGatewayTimeout)
				return
			}
			_, _ = io.WriteString(w, accountsJSON)
			return
		}
		once.Do(func() { close(dataStarted) })
		_, _ = io.WriteString(w, `{"response":[],"total":{"value":0}}`)
	}))
	t.Cleanup(srv.Close)
	s := accountsServer(t, srv, bearerIdentity())
	out, err := listCloudAccounts(t, s, "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out.Account == nil || out.Account.Name != "Acme" {
		t.Errorf("account = %+v: the lookup only answers once the data request has started", out.Account)
	}
}

// Concurrent calls for one token share a single lookup.
func TestConcurrentCallsShareOneLookup(t *testing.T) {
	var lookups atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/openid_customers") {
			lookups.Add(1)
			<-release
			_, _ = io.WriteString(w, accountsJSON)
			return
		}
		_, _ = io.WriteString(w, `{"response":[],"total":{"value":0}}`)
	}))
	t.Cleanup(srv.Close)
	s := accountsServer(t, srv, bearerIdentity())

	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := listCloudAccounts(t, s, "")
			if err == nil && (out.Account == nil || out.Account.Name != "Acme") {
				err = fmt.Errorf("account = %+v", out.Account)
			}
			errs <- err
		}()
	}
	time.Sleep(100 * time.Millisecond) // let every call reach the lookup
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := lookups.Load(); n != 1 {
		t.Errorf("lookups = %d, want 1", n)
	}
}
