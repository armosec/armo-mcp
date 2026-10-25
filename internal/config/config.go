package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr      string
	APIBaseURL      string
	DefaultPageSize int
	MaxPageSize     int
	MetricsAddr     string
	ServiceName     string
	Environment     string
	JaegerAgentHost string
	JaegerAgentPort string
	RateLimitPerMin int
	RateLimitBurst  int
	CacheTTL        time.Duration

	// OAuthEnabled turns on bearer authentication and RFC 9728 discovery.
	OAuthEnabled bool
	// OAuthIssuer, OAuthClientID and MCPResourceURL have no defaults, so a
	// forgotten setting fails startup instead of pointing at another
	// environment. OAuthClientID is the audience tokens must carry.
	OAuthIssuer    string
	OAuthClientID  string
	MCPResourceURL string

	// InvalidSettings lists variables Load could not parse; main refuses to
	// start on any, since a misread security flag must not fall back silently.
	InvalidSettings []string
}

func Load() Config {
	var invalid []string
	cfg := Config{
		ListenAddr:      envOr("ARMO_LISTEN_ADDR", ":8080"),
		APIBaseURL:      envOr("ARMO_API_BASE_URL", "api.armosec.io"),
		DefaultPageSize: 25,
		MaxPageSize:     100,
		MetricsAddr:     envOr("ARMO_METRICS_ADDR", ":9000"),
		ServiceName:     "armo-mcp",
		Environment:     envOr("ARMO_ENV", "dev"),
		JaegerAgentHost: os.Getenv("JAEGER_AGENT_HOST"),
		JaegerAgentPort: envOr("JAEGER_AGENT_PORT", "6831"),
		RateLimitPerMin: envInt("ARMO_RATE_LIMIT_PER_MIN", 120),
		RateLimitBurst:  envInt("ARMO_RATE_LIMIT_BURST", 30),
		CacheTTL:        envDurationSeconds("ARMO_CACHE_TTL_SECONDS", 30*time.Second),
		OAuthEnabled:    envBool("ARMO_OAUTH_ENABLED", false, &invalid),
		OAuthIssuer:     os.Getenv("ARMO_OAUTH_ISSUER"),
		OAuthClientID:   os.Getenv("ARMO_OAUTH_CLIENT_ID"),
		MCPResourceURL:  os.Getenv("ARMO_MCP_RESOURCE_URL"),
	}
	cfg.InvalidSettings = invalid
	return cfg
}

func envBool(key string, def bool, invalid *[]string) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		*invalid = append(*invalid, fmt.Sprintf("%s=%q is not a valid boolean (use true/false/1/0)", key, v))
		return def
	}
	return b
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDurationSeconds(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return def
}
