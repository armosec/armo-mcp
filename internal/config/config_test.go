package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	for _, k := range []string{
		"ARMO_LISTEN_ADDR", "ARMO_API_BASE_URL", "ARMO_METRICS_ADDR", "ARMO_ENV",
		"JAEGER_AGENT_HOST", "JAEGER_AGENT_PORT", "ARMO_RATE_LIMIT_PER_MIN",
		"ARMO_RATE_LIMIT_BURST", "ARMO_CACHE_TTL_SECONDS",
	} {
		_ = os.Unsetenv(k)
	}
	c := Load()
	if c.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", c.ListenAddr)
	}
	if c.APIBaseURL != "api.armosec.io" {
		t.Errorf("APIBaseURL = %q, want api.armosec.io", c.APIBaseURL)
	}
	if c.DefaultPageSize != 25 || c.MaxPageSize != 100 {
		t.Errorf("page sizes = %d/%d, want 25/100", c.DefaultPageSize, c.MaxPageSize)
	}
	if c.MetricsAddr != ":9000" {
		t.Errorf("MetricsAddr = %q, want :9000", c.MetricsAddr)
	}
	if c.ServiceName != "armo-mcp" {
		t.Errorf("ServiceName = %q, want armo-mcp", c.ServiceName)
	}
	if c.Environment != "dev" {
		t.Errorf("Environment = %q, want dev", c.Environment)
	}
	if c.JaegerAgentPort != "6831" {
		t.Errorf("JaegerAgentPort = %q, want 6831", c.JaegerAgentPort)
	}
	if c.RateLimitPerMin != 120 {
		t.Errorf("RateLimitPerMin = %d, want 120", c.RateLimitPerMin)
	}
	if c.RateLimitBurst != 30 {
		t.Errorf("RateLimitBurst = %d, want 30", c.RateLimitBurst)
	}
	if c.CacheTTL != 30*time.Second {
		t.Errorf("CacheTTL = %v, want 30s", c.CacheTTL)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("ARMO_API_BASE_URL", "api.us.armosec.io")
	if got := Load().APIBaseURL; got != "api.us.armosec.io" {
		t.Errorf("APIBaseURL = %q, want api.us.armosec.io", got)
	}
}

func TestLoadEnvOverrideNewFields(t *testing.T) {
	t.Setenv("JAEGER_AGENT_HOST", "jaeger-collector.local")
	t.Setenv("ARMO_RATE_LIMIT_PER_MIN", "240")
	t.Setenv("ARMO_CACHE_TTL_SECONDS", "60")

	c := Load()
	if c.JaegerAgentHost != "jaeger-collector.local" {
		t.Errorf("JaegerAgentHost = %q, want jaeger-collector.local", c.JaegerAgentHost)
	}
	if c.RateLimitPerMin != 240 {
		t.Errorf("RateLimitPerMin = %d, want 240", c.RateLimitPerMin)
	}
	if c.CacheTTL != 60*time.Second {
		t.Errorf("CacheTTL = %v, want 60s", c.CacheTTL)
	}
}

func TestLoadOAuthDefaults(t *testing.T) {
	for _, k := range []string{
		"ARMO_OAUTH_ENABLED", "ARMO_OAUTH_ISSUER", "ARMO_OAUTH_CLIENT_ID", "ARMO_MCP_RESOURCE_URL",
	} {
		_ = os.Unsetenv(k)
	}
	cfg := Load()
	if cfg.OAuthEnabled {
		t.Error("OAuth must default to disabled")
	}
	// No production default for either: a stage or dev deployment that forgot
	// them must fail at startup, not talk to prod-eu.
	if cfg.OAuthIssuer != "" {
		t.Errorf("OAuthIssuer = %q, want empty (no default)", cfg.OAuthIssuer)
	}
	if cfg.MCPResourceURL != "" {
		t.Errorf("MCPResourceURL = %q, want empty (no default)", cfg.MCPResourceURL)
	}
	if cfg.OAuthClientID != "" {
		t.Errorf("OAuthClientID = %q, want empty", cfg.OAuthClientID)
	}
}

func TestLoadOAuthFromEnv(t *testing.T) {
	t.Setenv("ARMO_OAUTH_ENABLED", "true")
	t.Setenv("ARMO_OAUTH_ISSUER", "https://idp.example.com")
	t.Setenv("ARMO_OAUTH_CLIENT_ID", "dev-client")
	t.Setenv("ARMO_MCP_RESOURCE_URL", "https://api-dev.armosec.io/mcp")
	cfg := Load()
	if !cfg.OAuthEnabled || cfg.OAuthIssuer != "https://idp.example.com" ||
		cfg.OAuthClientID != "dev-client" || cfg.MCPResourceURL != "https://api-dev.armosec.io/mcp" {
		t.Errorf("config = %+v", cfg)
	}
}

func TestOAuthEnabledUnparseableValueIsRecorded(t *testing.T) {
	// An unparseable security flag must not silently become its default.
	// Load has no error return, so it records the problem and main refuses to
	// start; this pins the recording half.
	for _, v := range []string{"yes", "on", "enabled", "1 "} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("ARMO_OAUTH_ENABLED", v)
			cfg := Load()
			if len(cfg.InvalidSettings) != 1 {
				t.Fatalf("InvalidSettings = %v, want exactly one entry", cfg.InvalidSettings)
			}
			got := cfg.InvalidSettings[0]
			if !strings.Contains(got, "ARMO_OAUTH_ENABLED") || !strings.Contains(got, v) {
				t.Errorf("entry %q should name both the variable and the value", got)
			}
			if cfg.OAuthEnabled {
				t.Error("an unparseable value must not enable OAuth")
			}
		})
	}
}

func TestOAuthEnabledValidValuesAreNotRecorded(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want bool
	}{{"true", true}, {"1", true}, {"TRUE", true}, {"false", false}, {"0", false}} {
		t.Run(tc.v, func(t *testing.T) {
			t.Setenv("ARMO_OAUTH_ENABLED", tc.v)
			cfg := Load()
			if len(cfg.InvalidSettings) != 0 {
				t.Errorf("InvalidSettings = %v, want none", cfg.InvalidSettings)
			}
			if cfg.OAuthEnabled != tc.want {
				t.Errorf("OAuthEnabled = %v, want %v", cfg.OAuthEnabled, tc.want)
			}
		})
	}
}

func TestUnsetOAuthEnabledIsNotRecorded(t *testing.T) {
	_ = os.Unsetenv("ARMO_OAUTH_ENABLED")
	if cfg := Load(); len(cfg.InvalidSettings) != 0 {
		t.Errorf("InvalidSettings = %v, want none when the variable is unset", cfg.InvalidSettings)
	}
}
