package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ProtectedResourcePath is the RFC 9728 discovery path the MCP spec requires.
const ProtectedResourcePath = "/.well-known/oauth-protected-resource"

// ProtectedResourcePathForMCP is the path-inserted form RFC 9728 section 3.1
// derives from https://host/mcp, for clients that do not follow the challenge.
const ProtectedResourcePathForMCP = ProtectedResourcePath + mcpPath

// RequiredScopes is what clients must request. They build `scope` from this
// document and from the 401 challenge, and Frontegg rejects an empty scope.
var RequiredScopes = []string{"openid", "profile", "email"}

// RequiredScopesParam is the same list in the space-delimited form the
// WWW-Authenticate `scope` auth-param takes (RFC 6750 section 3).
var RequiredScopesParam = strings.Join(RequiredScopes, " ")

type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
}

// ProtectedResourceHandler serves the metadata, unauthenticated by design.
func ProtectedResourceHandler(resourceURL, issuer string) http.Handler {
	body, _ := json.Marshal(protectedResourceMetadata{
		Resource:               resourceURL,
		AuthorizationServers:   []string{issuer},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        RequiredScopes,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}
