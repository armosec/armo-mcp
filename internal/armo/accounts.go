package armo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Accounts lists the accounts an OAuth user belongs to, with their names, from
// GET /openid_customers: the list the UI's account switcher shows. It needs a
// Frontegg token; an API key has no such list. The caller bounds it through ctx.
func (c *Client) Accounts(ctx context.Context, bearer string) ([]Account, error) {
	if bearer == "" {
		return nil, errors.New("listing accounts needs an OAuth token")
	}
	// Not tenant-scoped: an empty GUID leaves customerGUID off the URL.
	fullURL, err := c.resolveURL("/openid_customers", "")
	if err != nil {
		return nil, err
	}

	// Not through the breaker: this call depends on Frontegg, and names are
	// cosmetic, so its failures must not short-circuit every tenant's data calls.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+bearer)
	httpReq.Header.Set("accept", "application/json")
	res, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if err := responseError(res); err != nil {
		return nil, err
	}
	var out []Account
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode accounts: %w", err)
	}
	return out, nil
}
