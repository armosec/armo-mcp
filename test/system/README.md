# armo-mcp system tests

Black-box tests against a **deployed** armo-mcp endpoint (real MCP protocol +
access-key/GUID auth). Isolated behind the `systemtest` build tag, so they never
run in `go test ./...`.

## Run

    export ARMOMCP_SYSTEST_ENDPOINT="https://<env-host>/mcp"
    export ARMOMCP_SYSTEST_GUID="<test-tenant-customerGUID>"
    export ARMOMCP_SYSTEST_KEY="<test-tenant-access-key>"
    make system-test    # or: go test -tags systemtest ./test/system/... -v

With the env vars unset, the tests SKIP (green), so the tag can be run anywhere.

## What they assert
- Connect + ListTools advertises exactly the read-only tool set.
- Every tool returns a well-formed envelope (shape, not counts).
- Auth matrix: two-header works; packed `Bearer <guid>:<key>` works; a bogus key
  and a missing credential are rejected with no data (cross-credential cache lock).

## Credentials
Use a dedicated **read-only test tenant** for the target environment. Never commit
credentials.
