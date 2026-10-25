package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// mcpPath is the only path an MCP resource URL may have, because it is the
// only place Mount serves the MCP endpoint.
const mcpPath = "/mcp"

const resourceURLSetting = "ARMO_MCP_RESOURCE_URL"

// headerSafe reports whether s can sit inside a quoted-string auth-param
// without terminating it or smuggling in another parameter: no quote,
// backslash, whitespace, control or non-ASCII byte.
func headerSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// ValidateResourceURL checks the configured MCP resource URL (the
// ARMO_MCP_RESOURCE_URL setting). RFC 9728 requires the "resource" value in the
// metadata to match the URL clients actually call, and a typo breaks discovery
// without any error on the server, so it is rejected at startup.
//
// The accepted shape is deliberately narrow: an http or https URL with a host
// and exactly the path /mcp, and no userinfo, query or fragment. That is the one
// URL this server can serve correctly, and it keeps every attacker-shaped or
// operator-typo component out of the WWW-Authenticate header (which is built
// from the scheme and host only).
//
// The scheme is restricted to http/https because url.Parse accepts
// "localhost:8080/mcp" and reports "localhost" as the scheme.
func ValidateResourceURL(raw string) error {
	_, err := ResourceMetadataURL(raw)
	return err
}

// pathProblem explains why a resource URL's path is not exactly /mcp, and what
// value would work. It is the text an operator reads when startup is refused.
func pathProblem(u *url.URL) string {
	const fix = "set it to the bare scheme://host" + mcpPath
	switch {
	case u.RawPath == "" && u.Path == mcpPath+"/":
		return "the path must be exactly " + mcpPath + " with no trailing slash, because the server does not serve " + mcpPath + "/; " + fix
	case u.RawPath == "" && strings.HasSuffix(u.Path, mcpPath) && len(u.Path) > len(mcpPath):
		return "path-prefixed deployments are not supported yet; " + fix +
			", and if the server sits behind a path prefix, have the ingress strip the prefix before it reaches this server"
	case u.RawPath != "":
		return "the path must be exactly " + mcpPath + " written without percent-encoding; " + fix
	default:
		return "the path must be exactly " + mcpPath + "; " + fix
	}
}

// ResourceMetadataURL validates resourceURL and derives the protected-resource
// metadata URL that the 401 challenge advertises: the same scheme and host
// followed by ProtectedResourcePath. Mount serves the metadata at the mux
// root, so the advertised URL is only correct for a resource URL whose path is
// exactly /mcp, and anything else is rejected.
func ResourceMetadataURL(resourceURL string) (string, error) {
	if resourceURL == "" {
		// There is deliberately no default: a default would advertise one
		// environment's URL from every deployment that forgot to set it.
		return "", fmt.Errorf("%s is empty but is required when OAuth is enabled; set it to this server's public URL, scheme://host%s", resourceURLSetting, mcpPath)
	}
	u, err := url.Parse(resourceURL)
	if err != nil {
		return "", fmt.Errorf("%s %q is not a valid URL: %w", resourceURLSetting, resourceURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%s %q must be an absolute URL with an http or https scheme", resourceURLSetting, resourceURL)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("%s %q must include a host", resourceURLSetting, resourceURL)
	}
	// Clients send bearer tokens to this URL, so advertising it over plaintext
	// would invite them to disclose a credential on the wire. Loopback stays
	// allowed because local development has no certificate and no network to
	// intercept.
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return "", fmt.Errorf("%s %q must use https for a remote host; clients send bearer tokens to this URL, "+
			"so plaintext would expose them (http is allowed only for loopback: localhost, 127.0.0.0/8, ::1)",
			resourceURLSetting, resourceURL)
	}
	if u.User != nil {
		return "", fmt.Errorf("%s %q must not contain credentials", resourceURLSetting, resourceURL)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", fmt.Errorf("%s %q must not contain a query string (RFC 8707)", resourceURLSetting, resourceURL)
	}
	if u.Fragment != "" || strings.Contains(resourceURL, "#") {
		return "", fmt.Errorf("%s %q must not contain a fragment (RFC 9728)", resourceURLSetting, resourceURL)
	}
	// Only /mcp exactly: Mount serves at the mux root, and a prefix would 404
	// unless the ingress strips it, which cannot be told from here. Comparing
	// the decoded and as-written path rejects /mcp%22 and /m%63p.
	if u.Path != mcpPath || u.RawPath != "" {
		return "", fmt.Errorf("%s %q is not usable: %s", resourceURLSetting, resourceURL, pathProblem(u))
	}
	metadataURL := u.Scheme + "://" + u.Host + ProtectedResourcePath
	// Validate what is emitted, not the percent-encoded input.
	if !headerSafe(metadataURL) {
		return "", fmt.Errorf("%s %q contains characters that are not valid in a URL", resourceURLSetting, resourceURL)
	}
	return metadataURL, nil
}

// Challenge answers unauthenticated requests with the RFC 9728 challenge the
// MCP spec requires, so the client gets a 401 it can discover from. With no
// credential it sends the bare challenge (RFC 6750 section 3.1); with a
// rejected one it adds error="invalid_token" so a client can refresh. The
// rejection reason is logged, never sent. resourceMetadataURL must come from
// ResourceMetadataURL; Challenge panics if it is not header-safe.
func Challenge(a Authenticator, resourceMetadataURL string, next http.Handler) http.Handler {
	if !headerSafe(resourceMetadataURL) {
		panic(fmt.Sprintf("auth.Challenge: resourceMetadataURL %q is not safe to place in a header", resourceMetadataURL))
	}
	// scope is advertised here as well as in the protected-resource metadata:
	// newer MCP auth spec revisions have clients prefer the challenge's scope
	// and fall back to scopes_supported. Same list either way, so a client
	// reading either one builds a request Frontegg accepts.
	scope := ` scope="` + RequiredScopesParam + `"`
	bare := `Bearer resource_metadata="` + resourceMetadataURL + `",` + scope
	invalidToken := `Bearer error="invalid_token", resource_metadata="` + resourceMetadataURL + `",` + scope
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := a.Resolve(r.Header); err != nil {
			header := bare
			if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
				zap.L().Debug("mcp request without credentials, issuing challenge",
					zap.String("method", r.Method), zap.String("path", r.URL.Path))
			} else {
				header = invalidToken
				zap.L().Warn("mcp request rejected, issuing challenge",
					zap.String("method", r.Method), zap.String("path", r.URL.Path), zap.Error(err))
			}
			w.Header().Set("WWW-Authenticate", header)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Mount registers the GET-only metadata routes and the challenge-protected MCP
// endpoint. The challenge advertises the bare metadata path; the path-inserted
// form is served too, for clients that derive it from the resource URL.
func Mount(mux *http.ServeMux, a Authenticator, resourceURL, issuer string, mcpHandler http.Handler) error {
	metadataURL, err := ResourceMetadataURL(resourceURL)
	if err != nil {
		return err
	}
	metadata := ProtectedResourceHandler(resourceURL, issuer)
	mux.Handle("GET "+ProtectedResourcePath, metadata)
	mux.Handle("GET "+ProtectedResourcePathForMCP, metadata)
	mux.Handle(mcpPath, Challenge(a, metadataURL, mcpHandler))
	return nil
}

// isLoopbackHost: the only case where http is accepted for a resource URL or issuer.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
