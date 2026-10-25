package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armo-mcp/internal/armo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const testMetadataURL = "https://api.armosec.io" + ProtectedResourcePath

func TestChallengeRejectsWithoutToken(t *testing.T) {
	issuer, _ := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	var reached bool
	h := Challenge(a, testMetadataURL,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wa, "Bearer ") || !strings.Contains(wa, `resource_metadata="https://api.armosec.io/.well-known/oauth-protected-resource"`) {
		t.Errorf("WWW-Authenticate = %q", wa)
	}
	if reached {
		t.Error("the MCP handler must not run for an unauthenticated request")
	}
}

func TestChallengePassesValidToken(t *testing.T) {
	issuer, mint := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	var reached bool
	h := Challenge(a, testMetadataURL,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))

	tok := mint(map[string]any{
		"aud": []string{"mcp-client"}, "sub": "u1", "tenantId": "tenant-a",
		"roles": []string{"ReadOnly"}, "exp": time.Now().Add(time.Hour).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !reached {
		t.Fatalf("a valid token must reach the MCP handler; status was %d", rec.Code)
	}
}

func TestChallengeRejectsBadToken(t *testing.T) {
	issuer, _ := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	h := Challenge(a, testMetadataURL,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// failingAuth lets a test control the exact error text the authenticator
// produces, independent of go-oidc's wording.
type failingAuth struct{ err error }

func (f failingAuth) Resolve(http.Header) (armo.Identity, error) { return armo.Identity{}, f.err }

// captureLogs swaps the global zap logger for an in-memory one for the test.
func captureLogs(t *testing.T, level zapcore.Level) *observer.ObservedLogs {
	t.Helper()
	core, logs := observer.New(level)
	restore := zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(restore)
	return logs
}

// The challenge is generic: no part of the validation error reaches the client,
// in the header or the body. Checked with a real expired token through the real
// authenticator, so the test also proves go-oidc's text is what we are guarding
// against, not a string we invented.
func TestChallengeDoesNotLeakValidationError(t *testing.T) {
	issuer, mint := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	expired := mint(map[string]any{
		"aud": []string{"mcp-client"}, "sub": "u1", "tenantId": "tenant-a",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	hdr := http.Header{"Authorization": {"Bearer " + expired}}
	_, resolveErr := a.Resolve(hdr)
	if resolveErr == nil || !strings.Contains(resolveErr.Error(), "expired") {
		t.Fatalf("precondition: Resolve should fail with an expiry error, got %v", resolveErr)
	}

	h := Challenge(a, testMetadataURL, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header = hdr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	want := `Bearer error="invalid_token", resource_metadata="` + testMetadataURL + `", scope="` + RequiredScopesParam + `"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want exactly %q", got, want)
	}
	everything := rec.Body.String()
	for k, v := range rec.Header() {
		everything += k + ": " + strings.Join(v, ",") + "\n"
	}
	for _, leak := range []string{"expired", "oidc", "unauthenticated", "verif", "error_description"} {
		if strings.Contains(strings.ToLower(everything), leak) {
			t.Errorf("response leaks %q: %s", leak, everything)
		}
	}
}

// The detail the client does not get must be in the logs.
func TestChallengeLogsTheRealReason(t *testing.T) {
	logs := captureLogs(t, zapcore.DebugLevel)
	h := Challenge(failingAuth{errors.New("oidc: token is expired")}, testMetadataURL,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer some.jwt.value")
	h.ServeHTTP(httptest.NewRecorder(), req)

	entries := logs.FilterLevelExact(zapcore.WarnLevel).All()
	if len(entries) != 1 {
		t.Fatalf("want 1 warn entry, got %d (%v)", len(entries), logs.All())
	}
	if got := entries[0].ContextMap()["error"]; got != "oidc: token is expired" {
		t.Errorf("logged error = %v, want the real reason", got)
	}
	for _, e := range logs.All() {
		if strings.Contains(e.Message+" "+toString(e.ContextMap()), "some.jwt.value") {
			t.Error("the token itself must never be logged")
		}
	}
}

// A request with no Authorization header is ordinary discovery traffic and
// must not produce warnings.
func TestChallengeMissingCredentialIsNotAWarning(t *testing.T) {
	logs := captureLogs(t, zapcore.DebugLevel)
	h := Challenge(failingAuth{errors.New("unauthenticated: missing Bearer credential")}, testMetadataURL,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/mcp", nil))

	if n := logs.FilterLevelExact(zapcore.WarnLevel).Len(); n != 0 {
		t.Errorf("got %d warn entries for a credential-less request, want 0", n)
	}
}

// The two cases are distinguishable: no credential is plain discovery and gets
// the bare challenge; a rejected credential also gets error="invalid_token"
// (RFC 6750), and never an error_description.
func TestChallengeShapeDependsOnWhetherACredentialWasPresented(t *testing.T) {
	captureLogs(t, zapcore.DebugLevel)
	h := Challenge(failingAuth{errors.New("oidc: token is expired")}, testMetadataURL,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	bare := `Bearer resource_metadata="` + testMetadataURL + `", scope="` + RequiredScopesParam + `"`
	invalid := `Bearer error="invalid_token", resource_metadata="` + testMetadataURL + `", scope="` + RequiredScopesParam + `"`

	cases := []struct {
		name, authz, want string
	}{
		{"no header", "", bare},
		{"blank header", "   ", bare},
		{"bearer token rejected", "Bearer some.jwt.value", invalid},
		{"wrong scheme rejected", "Basic dXNlcjpwYXNz", invalid},
		{"empty bearer rejected", "Bearer ", invalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if c.authz != "" {
				req.Header.Set("Authorization", c.authz)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != c.want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, c.want)
			}
		})
	}
}

func toString(m map[string]any) string {
	var b strings.Builder
	for k, v := range m {
		b.WriteString(k)
		b.WriteString("=")
		if s, ok := v.(string); ok {
			b.WriteString(s)
		}
		b.WriteString(" ")
	}
	return b.String()
}

func TestValidateResourceURL(t *testing.T) {
	good := []string{
		"https://api.armosec.io/mcp",
		"http://localhost:8080/mcp",
		"http://127.0.0.1:8080/mcp",
		"http://[::1]:8080/mcp",
		"https://api.eu.armosec.io/mcp",
	}
	for _, u := range good {
		if err := ValidateResourceURL(u); err != nil {
			t.Errorf("ValidateResourceURL(%q) = %v, want nil", u, err)
		}
	}
	bad := map[string]string{
		"":                                            "empty",
		"api.armosec.io/mcp":                          "no scheme",
		"localhost:8080/mcp":                          "host:port parsed as scheme",
		"/mcp":                                        "path only",
		"https:///mcp":                                "no host",
		"https://":                                    "no host",
		"ftp://api.armosec.io/mcp":                    "wrong scheme",
		"http://api.armosec.io/mcp":                   "plaintext to a remote host",
		"https://api.armosec.io/mcp#x":                "fragment",
		"https://api.armosec.io/mcp#":                 "empty fragment",
		"https://api.armosec.io/mcp?x=1":              "query string",
		"https://api.armosec.io/mcp?":                 "empty query string",
		"https://user:pw@api.armosec.io/mcp":          "credentials in the URL",
		"https://api.armosec.io":                      "no path",
		"https://api.armosec.io/":                     "root path",
		"https://api.armosec.io/mcp/":                 "trailing slash is not the served path",
		"https://api.armosec.io/prefix/mcp":           "path prefix is not supported",
		"https://api.armosec.io/other":                "wrong path",
		"https://api armosec.io/mcp":                  "space in host",
		"https://api.armosec.io/\"mcp":                "literal quote",
		"https://%zz/mcp":                             "unparseable",
		"https://api.armosec.io/mcp%22":               "percent-encoded quote decodes into the path",
		"https://api.armosec.io/mcp%22,%20foo=%22bar": "percent-encoded auth-param injection",
		"https://api.armosec.io/mcp%5C":               "percent-encoded backslash",
		"https://api.armosec.io/m%63p":                "encoded spelling of /mcp is not the as-served path",
	}
	for u, why := range bad {
		err := ValidateResourceURL(u)
		if err == nil {
			t.Errorf("ValidateResourceURL(%q) = nil, want an error (%s)", u, why)
			continue
		}
		if !strings.Contains(err.Error(), "ARMO_MCP_RESOURCE_URL") {
			t.Errorf("error for %q does not name the setting: %v", u, err)
		}
	}

	// No default resource URL exists, so empty gets its own message.
	if err := ValidateResourceURL(""); err == nil ||
		!strings.Contains(err.Error(), "ARMO_MCP_RESOURCE_URL") || !strings.Contains(err.Error(), "required when OAuth is enabled") {
		t.Errorf("ValidateResourceURL(\"\") = %v, want one saying the setting is required", err)
	}

	// The message is what an operator reads when startup is refused, so it must
	// diagnose the actual mistake, echo the value, name the setting and say what
	// would work.
	msgs := []struct {
		in      string
		want    []string
		mustNot []string
	}{
		{"https://api.armosec.io/prefix/mcp",
			[]string{"ARMO_MCP_RESOURCE_URL", "https://api.armosec.io/prefix/mcp", "path-prefixed deployments are not supported",
				"bare scheme://host/mcp", "ingress strip the prefix"}, nil},
		{"https://api.armosec.io/mcp/",
			[]string{"ARMO_MCP_RESOURCE_URL", "https://api.armosec.io/mcp/", "exactly /mcp with no trailing slash",
				"does not serve /mcp/", "bare scheme://host/mcp"},
			[]string{"prefix"}},
		{"https://api.armosec.io",
			[]string{"ARMO_MCP_RESOURCE_URL", "must be exactly /mcp", "bare scheme://host/mcp"},
			[]string{"prefix", "trailing slash"}},
		{"https://api.armosec.io/other",
			[]string{"must be exactly /mcp", "bare scheme://host/mcp"},
			[]string{"prefix", "trailing slash"}},
	}
	for _, m := range msgs {
		err := ValidateResourceURL(m.in)
		if err == nil {
			t.Errorf("ValidateResourceURL(%q) = nil", m.in)
			continue
		}
		for _, w := range m.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("error for %q lacks %q: %v", m.in, w, err)
			}
		}
		for _, w := range m.mustNot {
			if strings.Contains(err.Error(), w) {
				t.Errorf("error for %q must not mention %q: %v", m.in, w, err)
			}
		}
	}
}

func TestResourceMetadataURL(t *testing.T) {
	cases := map[string]string{
		"https://api.armosec.io/mcp": "https://api.armosec.io" + ProtectedResourcePath,
		"http://localhost:8080/mcp":  "http://localhost:8080" + ProtectedResourcePath,
	}
	for in, want := range cases {
		got, err := ResourceMetadataURL(in)
		if err != nil || got != want {
			t.Errorf("ResourceMetadataURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// What was previously blessed: a prefix produced a URL Mount did not serve.
	if got, err := ResourceMetadataURL("https://api.armosec.io/prefix/mcp"); err == nil {
		t.Errorf("a path-prefixed resource URL must be rejected, got %q", got)
	}
	if _, err := ResourceMetadataURL("not a url"); err == nil {
		t.Error("ResourceMetadataURL must reject an invalid resource URL")
	}
}

// Whatever ResourceMetadataURL accepts must be safe to put in the header, and
// must be exactly what Mount serves. Property-style over the inputs that
// mattered: the output of every accepted input is header-safe.
func TestResourceMetadataURLOutputIsHeaderSafe(t *testing.T) {
	inputs := []string{
		"https://api.armosec.io/mcp", "http://localhost:8080/mcp",
		"https://api.armosec.io/mcp%22", "https://api.armosec.io/mcp%22,%20foo=%22bar",
		"https://ex%C3%A9.com/mcp", "https://api.armosec.io/mcp%0d%0a",
	}
	for _, in := range inputs {
		out, err := ResourceMetadataURL(in)
		if err != nil {
			continue
		}
		if !headerSafe(out) {
			t.Errorf("ResourceMetadataURL(%q) = %q, which is not header-safe", in, out)
		}
	}
	if _, err := ResourceMetadataURL("https://ex%C3%A9.com/mcp"); err == nil {
		t.Error("a non-ASCII host must be rejected (punycode is required); it would otherwise reach the header")
	}
}

func TestHeaderSafe(t *testing.T) {
	for _, s := range []string{"https://a.example/.well-known/x", "http://localhost:8080/p"} {
		if !headerSafe(s) {
			t.Errorf("headerSafe(%q) = false", s)
		}
	}
	for _, s := range []string{`a"b`, `a\b`, "a b", "a\tb", "a\r\nb", "a\x7fb", "ex\u00e9"} {
		if headerSafe(s) {
			t.Errorf("headerSafe(%q) = true", s)
		}
	}
}

// Challenge is exported and interpolates its URL into a header, so it refuses
// an unsafe one at construction instead of emitting an injectable challenge.
func TestChallengePanicsOnUnsafeMetadataURL(t *testing.T) {
	for _, u := range []string{`https://h/x", foo="bar`, "https://h/\r\nX: y", `https://h/\`} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Challenge(%q) did not panic", u)
				}
			}()
			Challenge(failingAuth{errors.New("x")}, u, http.NotFoundHandler())
		}()
	}
}

// Mount is the one place routes are registered. These requests go through a
// real ServeMux, so they prove the method-prefixed pattern is well formed (a
// malformed one panics in Mount) and that it actually restricts the method.
func TestMountRoutes(t *testing.T) {
	issuer, mint := newTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	var reached bool
	mux := http.NewServeMux()
	if err := Mount(mux, a, "https://api.armosec.io/mcp", issuer,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	do := func(method, path, authz string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	t.Run("metadata GET is public", func(t *testing.T) {
		rec := do(http.MethodGet, ProtectedResourcePath, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"resource":"https://api.armosec.io/mcp"`) {
			t.Errorf("body = %s", rec.Body)
		}
	})
	t.Run("metadata rejects POST", func(t *testing.T) {
		if rec := do(http.MethodPost, ProtectedResourcePath, ""); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})
	// RFC 9728 section 3.1: for resource https://api.armosec.io/mcp the
	// metadata URL is https://api.armosec.io/.well-known/oauth-protected-resource/mcp.
	t.Run("RFC 9728 path-inserted metadata URL serves the same document", func(t *testing.T) {
		const rfcPath = "/.well-known/oauth-protected-resource/mcp"
		if ProtectedResourcePathForMCP != rfcPath {
			t.Fatalf("ProtectedResourcePathForMCP = %q, want %q", ProtectedResourcePathForMCP, rfcPath)
		}
		bare := do(http.MethodGet, ProtectedResourcePath, "")
		rfc := do(http.MethodGet, rfcPath, "")
		if rfc.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rfc.Code)
		}
		if rfc.Body.String() != bare.Body.String() {
			t.Errorf("documents differ:\n bare: %s\n rfc:  %s", bare.Body, rfc.Body)
		}
		if got := rfc.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
	})
	t.Run("RFC 9728 path-inserted metadata URL rejects POST", func(t *testing.T) {
		if rec := do(http.MethodPost, ProtectedResourcePathForMCP, ""); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})
	t.Run("RFC 9728 path-inserted metadata URL is public", func(t *testing.T) {
		// No Authorization header on the request above either; assert that a
		// junk one does not turn the endpoint into a challenge.
		if rec := do(http.MethodGet, ProtectedResourcePathForMCP, "Bearer junk"); rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
	t.Run("mcp without token gets the challenge", func(t *testing.T) {
		rec := do(http.MethodPost, "/mcp", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if wa := rec.Header().Get("WWW-Authenticate"); !strings.Contains(wa, `resource_metadata="https://api.armosec.io/.well-known/oauth-protected-resource"`) {
			t.Errorf("WWW-Authenticate = %q", wa)
		}
		if reached {
			t.Error("handler ran without authentication")
		}
	})
	t.Run("mcp with a valid token reaches the handler", func(t *testing.T) {
		tok := mint(map[string]any{
			"aud": []string{"mcp-client"}, "sub": "u1", "tenantId": "tenant-a",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		do(http.MethodPost, "/mcp", "Bearer "+tok)
		if !reached {
			t.Error("valid token did not reach the handler")
		}
	})
}

// A bad resource URL must fail Mount and leave nothing registered, so main can
// refuse to start.
func TestMountRejectsBadResourceURL(t *testing.T) {
	mux := http.NewServeMux()
	err := Mount(mux, failingAuth{errors.New("x")}, "api.armosec.io/mcp", "https://issuer.example",
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err == nil || !strings.Contains(err.Error(), "ARMO_MCP_RESOURCE_URL") {
		t.Fatalf("Mount error = %v, want one naming ARMO_MCP_RESOURCE_URL", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("/mcp status = %d after a failed Mount, want 404 (nothing registered)", rec.Code)
	}
}
