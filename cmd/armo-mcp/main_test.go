package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/armosec/armo-mcp/internal/auth"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/armosec/armo-mcp/internal/config"
)

// The re-executed test binary runs runHTTP, or main itself, instead of the tests.
const (
	runHTTPChildEnv = "ARMO_MCP_TEST_RUN_HTTP_CHILD"
	runMainChildEnv = "ARMO_MCP_TEST_RUN_MAIN_CHILD"
)

func TestMain(m *testing.M) {
	switch {
	case os.Getenv(runHTTPChildEnv) == "1":
		runHTTP(config.Load())
		os.Exit(0) // only reached after a graceful shutdown
	case os.Getenv(runMainChildEnv) == "1":
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

// startChild launches the server in a subprocess with the given OAuth settings.
func startChild(t *testing.T, listen string, env map[string]string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		runHTTPChildEnv+"=1",
		"ARMO_LISTEN_ADDR="+listen,
		"ARMO_METRICS_ADDR="+freeAddr(t),
	)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	return cmd, &out
}

// stubIssuer serves just enough OIDC discovery for NewOAuthAuthenticator.
func stubIssuer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"jwks_uri":                              srv.URL + "/jwks",
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

// The central property of the OAuth change: when OAuth is enabled and its
// configuration is wrong, the process must exit non-zero before it serves
// anything, never come up unauthenticated or on the API-key path.
func TestOAuthEnabledFailsClosedAtStartup(t *testing.T) {
	good := stubIssuer(t)
	cases := []struct {
		name    string
		env     map[string]string
		wantMsg string
	}{
		{"invalid resource URL",
			map[string]string{"ARMO_OAUTH_ISSUER": good, "ARMO_OAUTH_CLIENT_ID": "c", "ARMO_MCP_RESOURCE_URL": "api.armosec.io/mcp"},
			"ARMO_MCP_RESOURCE_URL"},
		{"path-prefixed resource URL",
			map[string]string{"ARMO_OAUTH_ISSUER": good, "ARMO_OAUTH_CLIENT_ID": "c", "ARMO_MCP_RESOURCE_URL": "https://api.armosec.io/prefix/mcp"},
			"ARMO_MCP_RESOURCE_URL"},
		{"unreachable issuer",
			map[string]string{"ARMO_OAUTH_ISSUER": "http://127.0.0.1:1", "ARMO_OAUTH_CLIENT_ID": "c", "ARMO_MCP_RESOURCE_URL": "http://127.0.0.1:1/mcp"},
			"authenticator could not be built"},
		// No production default: a stage or dev deployment that sets only
		// ARMO_OAUTH_ENABLED and the client ID must not reach discovery.
		{"missing issuer",
			map[string]string{"ARMO_OAUTH_CLIENT_ID": "c", "ARMO_MCP_RESOURCE_URL": "http://127.0.0.1:1/mcp"},
			"ARMO_OAUTH_ISSUER"},
		{"missing resource URL",
			map[string]string{"ARMO_OAUTH_ISSUER": good, "ARMO_OAUTH_CLIENT_ID": "c"},
			"ARMO_MCP_RESOURCE_URL"},
		{"only the enable flag and client ID set",
			map[string]string{"ARMO_OAUTH_CLIENT_ID": "c"},
			"ARMO_MCP_RESOURCE_URL"},
		{"missing client ID",
			map[string]string{"ARMO_OAUTH_ISSUER": good, "ARMO_MCP_RESOURCE_URL": "http://127.0.0.1:1/mcp"},
			"authenticator could not be built"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			listen := freeAddr(t)
			env := map[string]string{"ARMO_OAUTH_ENABLED": "true"}
			for k, v := range c.env {
				env[k] = v
			}
			cmd, out := startChild(t, listen, env)

			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				var ee *exec.ExitError
				if !errors.As(err, &ee) || ee.ExitCode() != 1 {
					t.Fatalf("want exit code 1, got %v\noutput:\n%s", err, out)
				}
			case <-time.After(20 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("process still running: it must not start serving\noutput:\n%s", out)
			}

			if !strings.Contains(out.String(), c.wantMsg) {
				t.Errorf("output does not mention %q:\n%s", c.wantMsg, out)
			}
			// runHTTP logs "listening on" immediately before ListenAndServe.
			if strings.Contains(out.String(), "listening on") {
				t.Errorf("the server reached its listen step:\n%s", out)
			}
			if conn, err := net.DialTimeout("tcp", listen, time.Second); err == nil {
				_ = conn.Close()
				t.Errorf("something is listening on %s after a failed startup", listen)
			}
		})
	}
}

// Positive control. Without it the failure cases above would also pass if the
// harness itself were broken (child never starting, wrong binary, and so on).
// A correctly configured OAuth server comes up and answers /mcp with the 401
// challenge.
func TestOAuthEnabledStartsAndChallenges(t *testing.T) {
	listen := freeAddr(t)
	cmd, out := startChild(t, listen, map[string]string{
		"ARMO_OAUTH_ENABLED":    "true",
		"ARMO_OAUTH_ISSUER":     stubIssuer(t),
		"ARMO_OAUTH_CLIENT_ID":  "c",
		"ARMO_MCP_RESOURCE_URL": "http://" + listen + "/mcp",
	})
	t.Cleanup(func() { _ = cmd.Process.Signal(syscall.SIGTERM); _ = cmd.Wait() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var resp *http.Response
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+listen+"/mcp", strings.NewReader("{}"))
		var err error
		if resp, err = http.DefaultClient.Do(req); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("server never came up: %v\noutput:\n%s", err, out)
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	// The challenge advertises the scope as well as the metadata URL; newer MCP
	// clients prefer it over scopes_supported when building their request.
	want := fmt.Sprintf(`Bearer resource_metadata="http://%s/.well-known/oauth-protected-resource", scope=%q`, listen, auth.RequiredScopesParam)
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// main refuses an unparseable setting before it picks a transport, so an
// operator's "yes" cannot bring an intended OAuth-only server up on the API-key
// path. runHTTP is never reached, which is why this runs main itself.
func TestMainRefusesUnparseableSetting(t *testing.T) {
	for _, stdio := range []bool{false, true} {
		args := []string{}
		if stdio {
			args = append(args, "-stdio")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], args...)
		cmd.Env = append(os.Environ(),
			runMainChildEnv+"=1",
			"ARMO_OAUTH_ENABLED=yes",
			"ARMO_LISTEN_ADDR="+freeAddr(t),
			"ARMO_METRICS_ADDR="+freeAddr(t),
		)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			t.Fatalf("stdio=%v: want exit code 1, got %v\noutput:\n%s", stdio, err, out)
		}
		if !strings.Contains(string(out), "ARMO_OAUTH_ENABLED") || !strings.Contains(string(out), "refusing to start") {
			t.Errorf("stdio=%v: output does not name the setting and the refusal:\n%s", stdio, out)
		}
	}
}

// An oversized request is refused before anything reads it into memory. In
// API-key mode nothing authenticates the caller before the body is read, so
// without this limit any client could make the pod buffer gigabytes.
func TestOversizedRequestBodyIsRefused(t *testing.T) {
	listen := freeAddr(t)
	cmd, out := startChild(t, listen, nil)
	t.Cleanup(func() { _ = cmd.Process.Signal(syscall.SIGTERM); _ = cmd.Wait() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listen+"/healthz", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("server never came up: %v\noutput:\n%s", err, out)
		case <-time.After(100 * time.Millisecond):
		}
	}

	body := bytes.Repeat([]byte("a"), maxRequestBody+1)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+listen+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}
