# Security brief view (MCP App)

`show_security_brief` is the server's first [MCP App](https://claude.com/docs/connectors/building/mcp-apps/getting-started):
a tool whose result a supporting client renders as an interactive view instead of
plain text. It is a proof of concept.

## What the user sees

Asking "show my ARMO security brief" in a client that supports MCP Apps opens a view with:

- four totals: critical CVEs, runtime incidents, attack paths, security risks
- a CVE severity bar and a CVE table, filterable by severity, in use and exploitable
- the latest runtime incidents, attack paths and security risks
- an account picker (when the login can see several accounts) and a refresh button
- an **Ask Claude** button that posts a message to the chat asking what to fix first

A client without MCP Apps support (Claude Code, Cursor, VS Code today) ignores the view
and shows the tool result like any other: the counts, in the usual envelope.

## How it works

```
show_security_brief  ──_meta.ui.resourceUri──▶  ui://armo/security-brief
        │                                               │
        │ result: counts, one row per section           │ resources/read: the HTML
        ▼                                               ▼
     the host renders the HTML in a sandboxed iframe and hands it the result
        │
        └─ the view calls the existing query tools through the host
           (query_vulnerabilities, query_incidents, query_attack_chains,
            query_risks, list_accounts, show_security_brief)
```

Everything is in `internal/tools/securitybrief.go` and `internal/tools/ui/security-brief.html`.

**The tool.** `show_security_brief` takes only `account`. It returns the standard
envelope with seven rows: `{"section": "vulnerabilities", "severity": "Critical", "total": N}`
for each severity, then `incidents`, `attack_chains` and `risks`. Each total is one
single-row query against the backend, run together. A section that fails is returned as
`{"section": ..., "unavailable": true}` with a `note` on the envelope, so one failing
backend endpoint does not blank the whole brief; if every section fails, the call fails.
It goes through the same call funnel as every other tool (auth, account selection, rate
limit, cache, audit log).

**The link.** The tool definition carries `_meta.ui.resourceUri` (and the deprecated flat
`_meta["ui/resourceUri"]`, which the official helpers still emit). The Go SDK has no MCP
Apps helpers, so these are set by hand on `mcp.Tool.Meta` and `mcp.ResourceContents.Meta`.

**The resource.** `ui://armo/security-brief` has MIME type `text/html;profile=mcp-app`
and returns the embedded HTML with this `_meta.ui`:

| Field | Value | Why |
|---|---|---|
| `csp.resourceDomains` | `["https://unpkg.com"]` | the only external origin the view loads from: the MCP Apps client script |
| `domain` | first 32 hex chars of SHA-256 of `ARMO_MCP_RESOURCE_URL`, plus `.claudemcpcontent.com` | the value Claude requires; computed, never hardcoded |
| `prefersBorder` | `false` | the view draws its own cards |

The view makes no network requests of its own (`connectDomains` is unset, so the sandbox
blocks them). All data reaches it through the host, which calls this server's tools as
the signed-in user. The view stores nothing.

**The view.** One self-contained HTML file with no build step. It imports the
`@modelcontextprotocol/ext-apps` client, pinned to 1.7.5, from unpkg, calls
`App.connect()`, draws the counts from the tool result the host delivers, and loads the
tables with `callServerTool`. It follows the host's light or dark theme.

## Configuration

`_meta.ui.domain` is derived from `ARMO_MCP_RESOURCE_URL`, hashed exactly as written. It
must therefore be the URL users enter for the connector, for example
`https://api.armosec.io/mcp`. When the variable is unset (stdio, local runs without
OAuth) the domain is left out.

To try the view against a build behind a tunnel, set `ARMO_MCP_RESOURCE_URL` to the
tunnel's `/mcp` URL so the domain matches the URL Claude connects to.

## What has been verified

| Check | Status |
|---|---|
| Tool, resource and `_meta` cross the wire as specified (Go SDK v1.8.0) | unit tests |
| `claudeUIDomain` reproduces the example in Claude's documentation | unit test |
| The view connects, renders and calls tools with the real ext-apps 1.7.5 client | checked by hand against a minimal fake host page |
| The view renders in Claude (claude.ai or Claude Desktop) | **not verified**: needs this build on a public HTTPS URL added as a custom connector |
| Claude accepts the `_meta.ui.domain` value | **not verified** |
| `make system-test` with the new tool | **not run**: it targets a deployed server |

## Known limits

- The client script comes from a public CDN at view time. Claude's documentation
  recommends serving it from your own origin or bundling it for production; inlining it
  into the HTML would remove the dependency and the `resourceDomains` entry.
- The server registers the tool for every client and does not check the client's
  `io.modelcontextprotocol/ui` capability first. Clients without it see one more
  ordinary tool.
- The view opens one tool call per section on every load and refresh, each counted
  against the per-account rate limit.
- **Ask Claude** sends a fixed prompt to the chat; it does not pass the rows on screen.
