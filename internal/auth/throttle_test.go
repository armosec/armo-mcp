package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Forged tokens fail signature verification against the cached keys, which is
// exactly when go-oidc refetches the JWKS. They must not reach the IdP.
func TestForgedTokensDoNotRefetchKeys(t *testing.T) {
	issuer, mint, jwksHits := newCountingTestIDP(t)
	a, err := NewOAuthAuthenticator(context.Background(), issuer, "mcp-client")
	if err != nil {
		t.Fatalf("NewOAuthAuthenticator: %v", err)
	}
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	forgeKnownKid := signWith(t, attackerKey, "test-key", issuer)
	forgeUnknownKid := signWith(t, attackerKey, "rotated-key", issuer)

	for i := 0; i < 10; i++ {
		if _, err := a.Resolve(bearer(forgeKnownKid(validClaims()))); err == nil {
			t.Fatal("forged token accepted")
		}
		if _, err := a.Resolve(bearer(forgeUnknownKid(validClaims()))); err == nil {
			t.Fatal("forged token accepted")
		}
	}
	if got := jwksHits.Load(); got > 1 {
		t.Errorf("20 forged tokens caused %d JWKS fetches, want at most 1", got)
	}

	if _, err := a.Resolve(bearer(mint(validClaims()))); err != nil {
		t.Fatalf("a valid token must still verify after the forged ones: %v", err)
	}
}

type countingTransport struct {
	calls int
	fail  bool
	body  string
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls++
	if c.fail {
		return nil, errors.New("upstream down")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Request:    req,
	}, nil
}

func throttleWithClock(next http.RoundTripper) (*refetchThrottle, *time.Time) {
	now := time.Unix(1_700_000_000, 0)
	th := newRefetchThrottle(next, 30*time.Second)
	th.now = func() time.Time { return now }
	return th, &now
}

func get(t *testing.T, rt http.RoundTripper, url string) (string, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestRefetchThrottleReplaysWithinInterval(t *testing.T) {
	up := &countingTransport{body: `{"keys":["v1"]}`}
	th, now := throttleWithClock(up)

	for i := 0; i < 5; i++ {
		body, err := get(t, th, "https://idp.example/jwks")
		if err != nil || body != `{"keys":["v1"]}` {
			t.Fatalf("call %d: body %q, err %v", i, body, err)
		}
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d within the interval, want 1", up.calls)
	}

	up.body = `{"keys":["v2"]}`
	*now = now.Add(31 * time.Second)
	if body, _ := get(t, th, "https://idp.example/jwks"); body != `{"keys":["v2"]}` || up.calls != 2 {
		t.Fatalf("after the interval: body %q, upstream calls %d; a rotated key must be picked up", body, up.calls)
	}
}

func TestRefetchThrottleKeepsLastGoodResponseWhenUpstreamFails(t *testing.T) {
	up := &countingTransport{body: `{"keys":["v1"]}`}
	th, now := throttleWithClock(up)
	_, _ = get(t, th, "https://idp.example/jwks")

	up.fail = true
	*now = now.Add(31 * time.Second)
	if _, err := get(t, th, "https://idp.example/jwks"); err == nil {
		t.Fatal("an upstream failure past the interval must surface")
	}
	if body, err := get(t, th, "https://idp.example/jwks"); err != nil || body != `{"keys":["v1"]}` {
		t.Fatalf("within the interval after a failure: body %q, err %v; want the last good keys", body, err)
	}
	if up.calls != 2 {
		t.Fatalf("upstream calls = %d, want 2", up.calls)
	}
}

func TestRefetchThrottleThrottlesFailuresWithNoCachedResponse(t *testing.T) {
	up := &countingTransport{fail: true}
	th, _ := throttleWithClock(up)
	for i := 0; i < 5; i++ {
		if _, err := get(t, th, "https://idp.example/jwks"); err == nil {
			t.Fatal("expected an error")
		}
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1: a down IdP must not be hammered either", up.calls)
	}
}

func TestRefetchThrottlePassesNonGET(t *testing.T) {
	up := &countingTransport{body: "ok"}
	th, _ := throttleWithClock(up)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodPost, "https://idp.example/token", nil)
		resp, err := th.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if up.calls != 3 {
		t.Fatalf("upstream calls = %d for 3 POSTs, want 3", up.calls)
	}
}
