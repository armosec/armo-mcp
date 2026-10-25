# Configuration and deployment

Notes for running armo-mcp yourself, for development or evaluation. To connect an
assistant to the server ARMO hosts, see [connecting.md](connecting.md).

## Settings

All configuration is environment variables. Defaults in brackets.

| Variable | Purpose |
|---|---|
| `ARMO_API_BASE_URL` | the ARMO backend to call [`api.armosec.io`] |
| `ARMO_LISTEN_ADDR` | HTTP listen address [`:8080`] |
| `ARMO_METRICS_ADDR` | Prometheus listen address, on its own mux [`:9000`] |
| `ARMO_RATE_LIMIT_PER_MIN` | per-account rate limit [`120`] |
| `ARMO_RATE_LIMIT_BURST` | burst allowance [`30`] |
| `ARMO_CACHE_TTL_SECONDS` | response cache lifetime [`30`] |
| `ARMO_ENV` | environment name, used in logs and traces [`dev`] |
| `JAEGER_AGENT_HOST` | tracing collector; empty disables tracing |
| `JAEGER_AGENT_PORT` | tracing collector port [`6831`] |
| `ARMO_OAUTH_ENABLED` | turn on the OAuth path [`false`] |
| `ARMO_OAUTH_ISSUER` | the Frontegg issuer for this environment, no default |
| `ARMO_OAUTH_CLIENT_ID` | the audience tokens must carry, no default |
| `ARMO_MCP_RESOURCE_URL` | this server's public URL, path exactly `/mcp`, no default |

### Why the OAuth settings have no defaults

A default would advertise one environment's URL from every deployment that forgot to
set it, which fails silently and in the worst possible direction. With
`ARMO_OAUTH_ENABLED=true` and any of the other three missing, the server refuses to
start rather than falling back to a weaker path.

A setting that cannot be parsed also stops startup. An `ARMO_OAUTH_ENABLED=yes` read
as false would turn an intended OAuth-only deployment into an API-key one, which is
the kind of silent downgrade worth crashing over.

`ARMO_OAUTH_ISSUER` and `ARMO_MCP_RESOURCE_URL` must be `https` unless the host is
loopback (`localhost`, `127.0.0.0/8`, `::1`). Discovery over plaintext would let anyone
on the path substitute the signing keys, and clients send bearer tokens to the resource
URL.

### Signing keys are refetched at most every 30 seconds

The OIDC library refetches the issuer's JWKS whenever a token fails signature
verification, which happens before any other check. Without a limit, every forged token
on an unauthenticated request would cost a call to Frontegg. The server allows one fetch
per 30 seconds and replays the last good key set in between. The cost is that a key
Frontegg rotates within 30 seconds of the last fetch is picked up up to 30 seconds late,
and tokens signed with it fail until then.

### The resource URL must have no path prefix

`ARMO_MCP_RESOURCE_URL` is rejected at startup unless its path is exactly `/mcp`. A
deployment behind a prefix-stripping gateway would work in principle, but the server
cannot tell from inside the pod which kind of proxy sits in front of it, and a loud
startup failure beats a silent 404 during discovery.

## Routing

The server has no hostname of its own. It shares the ARMO API host and takes the
`/mcp` prefix.

RFC 9728 discovery needs a route of its own. When a client calls `/mcp` without a
token, the server answers 401 with:

```
WWW-Authenticate: Bearer resource_metadata="https://api.armosec.io/.well-known/oauth-protected-resource"
```

and the client fetches exactly that URL next. **That path is not under `/mcp`**, so
without its own ingress rule it falls through to whatever owns `/` and 404s. Discovery
then fails at its first step, with nothing in this server's logs, because the request
never arrives.

Route `/.well-known/oauth-protected-resource` to the server as well as `/mcp` for this
reason. If a
gateway, WAF or CDN is ever placed in front of the API host, check that path still
reaches here.

## Running a single account over stdio

For local development against one account, without OAuth:

```bash
export ARMO_CUSTOMER_GUID=<customer-guid>
export ARMO_ACCESS_KEY=<access-key>
armo-mcp --stdio
```

Both variables are required. Logs go to stderr so they never corrupt the JSON-RPC
stream on stdout.

An access key carries the permissions of whoever created it and does not expire, which
is why the hosted deployment uses OAuth instead. Do not use this mode to serve more
than yourself.

## Development

```bash
make test          # unit tests
make build         # binary into ./bin
make run           # run locally
make system-test   # end-to-end tests
```
