package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/armosec/armo-mcp/internal/armo"
)

type Authenticator interface {
	Resolve(h http.Header) (armo.Identity, error)
}

type APIKeyAuthenticator struct{}

func (APIKeyAuthenticator) Resolve(h http.Header) (armo.Identity, error) {
	authz := h.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return armo.Identity{}, errors.New("unauthenticated: missing Bearer credential")
	}
	token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	guid := strings.TrimSpace(h.Get("X-Armo-Customer-Guid"))
	key := token
	// Packed single-credential form: "Bearer <customerGUID>:<accessKey>". Used by
	// hosts that only expose one credential field (e.g. ChatGPT's custom connector),
	// and only when the X-Armo-Customer-Guid header isn't supplied separately. GUID
	// and access key are UUIDs, so split on the first colon.
	if guid == "" {
		if i := strings.Index(token, ":"); i >= 0 {
			guid = strings.TrimSpace(token[:i])
			key = strings.TrimSpace(token[i+1:])
		}
	}
	if key == "" {
		return armo.Identity{}, errors.New("unauthenticated: empty access key")
	}
	if guid == "" {
		return armo.Identity{}, errors.New("unauthenticated: missing customer GUID (send X-Armo-Customer-Guid, or use Bearer <customerGUID>:<accessKey>)")
	}
	return armo.Identity{CustomerGUID: guid, APIKey: key}, nil
}

// StaticAuthenticator returns a fixed identity regardless of request headers.
// Used for local single-tenant deployments (stdio mode), where credentials come
// from the process environment rather than per-request headers.
type StaticAuthenticator struct {
	ID armo.Identity
}

func (s StaticAuthenticator) Resolve(http.Header) (armo.Identity, error) {
	if s.ID.CustomerGUID == "" || s.ID.APIKey == "" {
		return armo.Identity{}, errors.New("unauthenticated: missing ARMO_CUSTOMER_GUID or ARMO_ACCESS_KEY")
	}
	return s.ID, nil
}
