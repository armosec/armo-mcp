package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/armosec/armo-mcp/internal/armo"
	"github.com/coreos/go-oidc/v3/oidc"
)

// discoveryTimeout bounds every HTTP call the OIDC library makes: discovery at
// construction, and the JWKS fetches that happen later during verification.
// It is a variable so a test can shorten it.
var discoveryTimeout = 10 * time.Second

// OAuthAuthenticator resolves a Frontegg access token into an ARMO identity.
// It fails fast and drives the 401 challenge; the backend validates the token
// again and makes the real decision.
type OAuthAuthenticator struct {
	verifier *oidc.IDTokenVerifier
}

// tokenClaims: the active tenant (tenantId) is the default account. tenantIds
// only lists which other accounts a tool call may name; it never sets the default.
type tokenClaims struct {
	TenantID  string   `json:"tenantId"`
	TenantIDs []string `json:"tenantIds"`
}

// NewOAuthAuthenticator performs OIDC discovery against the Frontegg tenant
// and builds a verifier bound to clientID as the expected audience.
func NewOAuthAuthenticator(ctx context.Context, issuer, clientID string) (*OAuthAuthenticator, error) {
	if clientID == "" {
		// go-oidc would skip the audience check.
		return nil, errors.New("oauth: empty client ID")
	}
	if issuer == "" {
		return nil, errors.New("oauth: empty issuer: ARMO_OAUTH_ISSUER is required when OAuth is enabled")
	}
	// Discovery and JWKS decide which keys are trusted, so plaintext to a
	// remote issuer would let a network attacker mint accepted tokens.
	if iss, err := url.Parse(issuer); err != nil {
		return nil, fmt.Errorf("oauth: issuer %q is not a valid URL: %w", issuer, err)
	} else if iss.Scheme == "http" && !isLoopbackHost(iss.Hostname()) {
		return nil, fmt.Errorf("oauth: issuer %q must use https for a remote host; discovery and JWKS decide "+
			"which keys authenticate callers, so plaintext would let a network attacker mint accepted tokens "+
			"(http is allowed only for loopback)", issuer)
	}
	// go-oidc keeps this client for later JWKS fetches too, so the timeout and
	// the refetch throttle cover them as well as discovery.
	ctx = oidc.ClientContext(ctx, &http.Client{
		Timeout:   discoveryTimeout,
		Transport: newRefetchThrottle(http.DefaultTransport, keyRefetchInterval),
	})
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oauth: discovery against %s: %w", issuer, err)
	}
	return &OAuthAuthenticator{
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

func (a *OAuthAuthenticator) Resolve(h http.Header) (armo.Identity, error) {
	if h == nil {
		return armo.Identity{}, errors.New("unauthenticated: no request headers")
	}
	// The scheme is case-insensitive (RFC 6750); the token is used as received.
	authz := h.Get("Authorization")
	const scheme = "Bearer "
	if len(authz) < len(scheme) || !strings.EqualFold(authz[:len(scheme)], scheme) {
		return armo.Identity{}, errors.New("unauthenticated: missing Bearer credential")
	}
	raw := strings.TrimSpace(authz[len(scheme):])
	if raw == "" {
		return armo.Identity{}, errors.New("unauthenticated: empty bearer token")
	}

	idToken, err := a.verifier.Verify(context.Background(), raw)
	if err != nil {
		return armo.Identity{}, fmt.Errorf("unauthenticated: %w", err)
	}

	var claims tokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return armo.Identity{}, fmt.Errorf("unauthenticated: unreadable claims: %w", err)
	}
	if claims.TenantID == "" {
		return armo.Identity{}, errors.New("unauthenticated: token carries no tenantId")
	}

	// The tenant comes from the token, never a header.
	return armo.Identity{CustomerGUID: claims.TenantID, Bearer: raw, Tenants: claims.TenantIDs}, nil
}

var _ Authenticator = (*OAuthAuthenticator)(nil)
