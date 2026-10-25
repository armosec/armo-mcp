package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/armosec/armo-mcp/internal/cache"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"
)

// AccountInput is embedded in every tool input that reads account data, so a
// user who belongs to several ARMO accounts can pick one per call.
type AccountInput struct {
	Account string `json:"account,omitempty" jsonschema:"ARMO account to query: its customerGUID or exact name from list_accounts. Omit for the account you signed in to."`
}

func (a AccountInput) selectedAccount() string { return a.Account }

type accountSelector interface{ selectedAccount() string }

// AccountRef names the account a result came from.
type AccountRef struct {
	GUID string `json:"customerGUID" jsonschema:"the account's GUID"`
	Name string `json:"customerName,omitempty" jsonschema:"the account's name, when it could be looked up"`
}

type ListAccountsInput struct{}

// allowedAccounts is the active tenant first, then the token's other tenants.
// These are the accounts the backend accepts for this credential.
func allowedAccounts(ident armo.Identity) []string {
	out := []string{ident.CustomerGUID}
	for _, t := range ident.Tenants {
		if _, ok := findFold(out, t); !ok {
			out = append(out, t)
		}
	}
	return out
}

// findFold returns the entry of list equal to s ignoring case, in list's spelling.
func findFold(list []string, s string) (string, bool) {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return v, true
		}
	}
	return "", false
}

// accountError is a selection failure. Its message quotes the caller's input
// for the tool error; logs record only reason, never the input.
type accountError struct {
	reason string
	msg    string
}

func (e *accountError) Error() string { return e.msg }

func accountErrorReason(err error) string {
	var ae *accountError
	if errors.As(err, &ae) {
		return ae.reason
	}
	return "other"
}

// accountLookupTimeout bounds a name lookup so that a stalled
// /openid_customers cannot hold a tool call for long.
var accountLookupTimeout = 3 * time.Second

// accountLookupBackoff is how long a token's failed lookup is remembered, so
// an /openid_customers outage costs one call per token, not one per tool call.
var accountLookupBackoff = 30 * time.Second

var errAccountLookupBackoff = errors.New("account names are temporarily unavailable")

// accountLookup is one in-flight name lookup that concurrent calls for the
// same token wait on instead of starting their own.
type accountLookup struct {
	done  chan struct{}
	names []armo.Account
	err   error
}

func (s *Server) initAccountState() {
	s.accountOnce.Do(func() {
		s.accountFailures = cache.New[struct{}](accountLookupBackoff)
		s.accountInflight = map[string]*accountLookup{}
	})
}

// accountNames returns the caller's accounts with names, cached per token. An
// API key has no list, so it returns nil, as does a Server without a Client.
func (s *Server) accountNames(ctx context.Context, ident armo.Identity) ([]armo.Account, error) {
	if ident.Bearer == "" || s.Client == nil {
		return nil, nil
	}
	s.initAccountState()
	sum := sha256.Sum256([]byte(ident.Bearer))
	key := hex.EncodeToString(sum[:])
	if s.Accounts != nil {
		if names, ok := s.Accounts.Get(key); ok {
			return names, nil
		}
	}
	if _, failed := s.accountFailures.Get(key); failed {
		return nil, errAccountLookupBackoff
	}

	s.accountMu.Lock()
	l, running := s.accountInflight[key]
	if !running {
		l = &accountLookup{done: make(chan struct{})}
		s.accountInflight[key] = l
	}
	s.accountMu.Unlock()
	if !running {
		// Shared by every waiter, so it is not tied to one caller's cancellation.
		go s.runAccountLookup(context.WithoutCancel(ctx), ident, key, l)
	}
	select {
	case <-l.done:
		return l.names, l.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) runAccountLookup(ctx context.Context, ident armo.Identity, key string, l *accountLookup) {
	ctx, cancel := context.WithTimeout(ctx, accountLookupTimeout)
	defer cancel()
	l.names, l.err = s.Client.Accounts(ctx, ident.Bearer)
	if l.err != nil {
		s.accountFailures.Set(key, struct{}{})
		zap.L().Warn("account name lookup failed", zap.String("tenant", ident.CustomerGUID), zap.Error(l.err))
	} else if s.Accounts != nil {
		s.Accounts.Set(key, l.names)
	}
	s.accountMu.Lock()
	delete(s.accountInflight, key)
	s.accountMu.Unlock()
	close(l.done)
}

func nameOf(names []armo.Account, guid string) string {
	for _, a := range names {
		if strings.EqualFold(a.GUID, guid) {
			return a.Name
		}
	}
	return ""
}

// accountName is the best-effort name for a result label.
func (s *Server) accountName(ctx context.Context, ident armo.Identity, guid string) string {
	names, _ := s.accountNames(ctx, ident)
	return nameOf(names, guid)
}

// selectAccount points ident at the account the call asked for, or keeps the
// active one. It looks names up only when want is not one of the token's
// GUIDs; labelling the result with a name happens after the rate limiter.
func (s *Server) selectAccount(ctx context.Context, ident armo.Identity, want string) (armo.Identity, AccountRef, error) {
	allowed := allowedAccounts(ident)
	target := ident.CustomerGUID
	if want = strings.TrimSpace(want); want != "" {
		guid, ok := findFold(allowed, want)
		if !ok {
			names, namesErr := s.accountNames(ctx, ident)
			var err error
			if guid, err = matchAccount(allowed, names, namesErr, want); err != nil {
				return armo.Identity{}, AccountRef{}, err
			}
		}
		target = guid
	}
	ident.CustomerGUID = target
	return ident, AccountRef{GUID: target}, nil
}

// matchAccount resolves want, which is not one of the token's GUIDs, against
// the live account list. The list can be newer than the token's tenantIds, so
// an account found there but not in allowed needs a fresh sign-in.
func matchAccount(allowed []string, names []armo.Account, namesErr error, want string) (string, error) {
	signInAgain := &accountError{"sign_in_again", fmt.Sprintf("account %q was added after you signed in; sign in again to the ARMO connector to use it", want)}
	for _, a := range names {
		if strings.EqualFold(a.GUID, want) {
			return "", signInAgain
		}
	}
	var usable []string
	unavailable := false
	for _, a := range names {
		if !strings.EqualFold(strings.TrimSpace(a.Name), want) {
			continue
		}
		if _, ok := findFold(allowed, a.GUID); ok {
			usable = append(usable, a.GUID)
		} else {
			unavailable = true
		}
	}
	switch {
	case len(usable) > 1:
		return "", &accountError{"ambiguous_name", fmt.Sprintf("account name %q is ambiguous; pass one of these customerGUIDs: %s", want, strings.Join(usable, ", "))}
	case len(usable) == 1:
		return usable[0], nil
	case unavailable:
		return "", signInAgain
	case namesErr != nil:
		// Name the GUIDs that would work, since list_accounts cannot show names either.
		guids := append([]string{allowed[0] + " (active)"}, allowed[1:]...)
		return "", &accountError{"names_unavailable", fmt.Sprintf("could not look up account names (%v); pass one of these customerGUIDs instead: %s, or omit account for the active one", namesErr, strings.Join(guids, ", "))}
	default:
		return "", &accountError{"unknown_account", fmt.Sprintf("unknown account %q; call list_accounts for the accounts you can use", want)}
	}
}

// accountNamesUnavailable is list_accounts' note when the names lookup failed.
const accountNamesUnavailable = "Account names could not be looked up right now; the customerGUIDs are complete and can be passed as account."

func (s *Server) listAccounts(ctx context.Context, ident armo.Identity) (QueryResult, error) {
	names, err := s.accountNames(ctx, ident)
	allowed := allowedAccounts(ident)
	items := make([]map[string]any, 0, len(allowed))
	for i, g := range allowed {
		item := map[string]any{"customerGUID": g, "active": i == 0}
		if n := nameOf(names, g); n != "" {
			item["customerName"] = n
		}
		items = append(items, item)
	}
	out := QueryResult{Total: len(items), Page: 1, PageSize: len(items), Count: len(items), Items: items}
	if err != nil {
		out.Note = accountNamesUnavailable
	}
	return out, nil
}

func (s *Server) ListAccounts(ctx context.Context, req *mcp.CallToolRequest, in ListAccountsInput) (*mcp.CallToolResult, QueryResult, error) {
	return s.call(ctx, req, "list_accounts", in, s.listAccounts)
}
