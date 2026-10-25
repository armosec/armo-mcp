package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// keyRefetchInterval is the minimum time between two network fetches of the
// same URL. go-oidc refetches the JWKS whenever a token fails to verify against
// its cached keys, before any claim is checked, so without this every forged
// token on an unauthenticated request would cost a call to the IdP. A key
// rotated in less than this after the last fetch is picked up one interval late.
var keyRefetchInterval = 30 * time.Second

// maxCachedBody caps what the throttle will buffer. A JWKS or discovery
// document is a few KB.
const maxCachedBody = 1 << 20

// refetchThrottle lets at most one GET per URL reach the network per interval
// and replays the last successful response in between.
type refetchThrottle struct {
	next     http.RoundTripper
	interval time.Duration
	now      func() time.Time

	mu   sync.Mutex
	last map[string]*cachedFetch
}

type cachedFetch struct {
	at     time.Time
	status int
	header http.Header
	body   []byte // nil until a fetch succeeds
}

func newRefetchThrottle(next http.RoundTripper, interval time.Duration) *refetchThrottle {
	if next == nil {
		next = http.DefaultTransport
	}
	return &refetchThrottle{next: next, interval: interval, now: time.Now, last: map[string]*cachedFetch{}}
}

func (t *refetchThrottle) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return t.next.RoundTrip(req)
	}
	key := req.URL.String()

	t.mu.Lock()
	c := t.last[key]
	if c != nil && t.now().Sub(c.at) < t.interval {
		snap := *c
		t.mu.Unlock()
		if snap.body == nil {
			return nil, fmt.Errorf("fetch of %s throttled: last attempt failed less than %s ago", key, t.interval)
		}
		return snap.replay(req), nil
	}
	if c == nil {
		c = &cachedFetch{}
		t.last[key] = c
	}
	c.at = t.now()
	t.mu.Unlock()

	resp, err := t.next.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCachedBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCachedBody {
		return nil, fmt.Errorf("fetch of %s: response larger than %d bytes", key, maxCachedBody)
	}

	fresh := cachedFetch{status: resp.StatusCode, header: resp.Header.Clone(), body: body}
	t.mu.Lock()
	c.status, c.header, c.body = fresh.status, fresh.header, fresh.body
	t.mu.Unlock()
	return fresh.replay(req), nil
}

func (c *cachedFetch) replay(req *http.Request) *http.Response {
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", c.status, http.StatusText(c.status)),
		StatusCode:    c.status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        c.header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(c.body)),
		ContentLength: int64(len(c.body)),
		Request:       req,
	}
}
