package armo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sony/gobreaker"
)

// errAuthFailure marks 401/403 responses. It is wrapped (not returned bare) so
// that the breaker's IsSuccessful hook can identify auth failures via
// errors.Is and avoid counting them as circuit-breaker failures — an
// unauthorized/forbidden response is a client-credential problem, not a sign
// that the backend itself is unhealthy.
var errAuthFailure = errors.New("unauthorized")

// errClientRequest marks other 4xx responses (e.g. 400/404/429). Like auth
// failures, these stem from the request itself rather than backend health, so
// they are wrapped to keep them from tripping the breaker — otherwise a single
// caller sending bad requests could open the shared per-instance breaker for
// every tenant.
var errClientRequest = errors.New("client request error")

// ErrBackendUnavailable is returned when the circuit breaker is open (or
// half-open and throttling): the backend is being given time to recover, so
// the request is short-circuited rather than attempted. Callers can detect
// this via errors.Is without matching on error strings.
var ErrBackendUnavailable = errors.New("backend unavailable")

type Client struct {
	baseURL string
	http    *http.Client
	breaker *gobreaker.CircuitBreaker
}

func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	breaker := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name: "cadashboardbe",
		ReadyToTrip: func(c gobreaker.Counts) bool {
			return c.ConsecutiveFailures >= 5
		},
		Timeout: 30 * time.Second,
		IsSuccessful: func(err error) bool {
			// Only transport errors and 5xx responses indicate an unhealthy
			// backend and should trip the breaker. A success, an auth failure
			// (401/403) or any other 4xx client-request error must not.
			return err == nil || errors.Is(err, errAuthFailure) || errors.Is(err, errClientRequest)
		},
	})
	return &Client{baseURL: baseURL, http: httpClient, breaker: breaker}
}

func (c *Client) resolveURL(path, customerGUID string) (string, error) {
	base := c.baseURL
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}
	hostPart := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if !strings.Contains(hostPart, "/api/v") {
		base = strings.TrimRight(base, "/") + "/api/v1"
	}
	base = strings.TrimRight(base, "/")
	u, err := url.Parse(base + path)
	if err != nil {
		return "", err
	}
	if customerGUID != "" {
		q := u.Query()
		q.Set("customerGUID", customerGUID)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

func (c *Client) List(ctx context.Context, ident Identity, req ListRequest) (*ListResponse, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	// ListRequest.PageNum is 0-based, the backend's pageNum is 1-based: it serves pageNum 0 and 1
	// as the same first page, so sending the raw value repeats page 1 as page 2.
	body := map[string]any{"pageNum": req.PageNum + 1, "pageSize": req.PageSize}
	if len(req.InnerFilters) > 0 {
		body["innerFilters"] = req.InnerFilters
	}
	for k, v := range req.Extra {
		if k != "pageNum" && k != "pageSize" && k != "innerFilters" {
			body[k] = v
		}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	fullURL, err := c.resolveURL(req.Path, ident.CustomerGUID)
	if err != nil {
		return nil, err
	}

	result, err := c.breaker.Execute(func() (any, error) {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		// Send exactly one credential, so the backend never has to choose
		// between two identities for the same request.
		if ident.Bearer != "" {
			httpReq.Header.Set("Authorization", "Bearer "+ident.Bearer)
		} else {
			httpReq.Header.Set("x-api-key", ident.APIKey)
		}
		httpReq.Header.Set("content-type", "application/json")
		httpReq.Header.Set("accept", "application/json")

		res, err := c.http.Do(httpReq)
		if err != nil {
			// Transport-level failure (dial/timeout/etc): counts as a breaker failure.
			return nil, err
		}
		defer func() { _ = res.Body.Close() }()

		if err := statusError(res.StatusCode); err != nil {
			return nil, err
		}

		var env struct {
			Response json.RawMessage `json:"response"`
			Total    *struct {
				Value int `json:"value"`
			} `json:"total"`
			Cursor string `json:"cursor"`
		}
		if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		out := &ListResponse{Cursor: env.Cursor}
		if env.Total != nil {
			out.Total = env.Total.Value
		}
		if req.ResponseKey == "" {
			if len(env.Response) > 0 {
				if err := json.Unmarshal(env.Response, &out.Items); err != nil {
					return nil, fmt.Errorf("decode response array: %w", err)
				}
			}
		} else if len(env.Response) > 0 {
			var nested map[string]json.RawMessage
			if err := json.Unmarshal(env.Response, &nested); err != nil {
				return nil, fmt.Errorf("decode nested response object: %w", err)
			}
			if arr := nested[req.ResponseKey]; len(arr) > 0 {
				if err := json.Unmarshal(arr, &out.Items); err != nil {
					return nil, fmt.Errorf("decode nested array %q: %w", req.ResponseKey, err)
				}
			}
		}
		return out, nil
	})
	if err != nil {
		return nil, breakerError(err)
	}
	return result.(*ListResponse), nil
}

// statusError classifies a non-2xx status so the breaker counts only backend
// failures.
func statusError(code int) error {
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		// Wrapped via errAuthFailure so IsSuccessful can exempt it from tripping the breaker.
		return fmt.Errorf("%w: backend returned %d", errAuthFailure, code)
	}
	if code >= 400 && code < 500 {
		// Other 4xx are request-level errors, not backend health. Wrapped via
		// errClientRequest so IsSuccessful exempts them from the breaker.
		return fmt.Errorf("%w: backend returned %d", errClientRequest, code)
	}
	if code < 200 || code >= 300 {
		// 5xx (and any other non-2xx) responses indicate an unhealthy backend
		// and count as a breaker failure.
		return fmt.Errorf("backend error: status %d", code)
	}
	return nil
}

func breakerError(err error) error {
	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		return fmt.Errorf("%w: %w", ErrBackendUnavailable, err)
	}
	return err
}
