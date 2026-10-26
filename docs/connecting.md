# Connecting an assistant to ARMO

Connect your AI assistant to your ARMO security data. Ask about vulnerabilities,
Kubernetes and cloud posture, runtime incidents and attack paths in plain language,
and get answers from your own account.

ARMO hosts the server, so there is nothing to install. You connect to a URL and sign
in with your ARMO account.

It is read-only. Every tool is a query, and nothing it exposes can change your
account, start a scan, or alter a finding.

## What you can ask

> Which of my images have critical CVEs with a fix available?

> Show me runtime incidents from the last day and the workloads they touched.

> Which controls is my production cluster failing against NSA-CISA?

> Are any of my cloud accounts failing CIS benchmarks?

> What attack paths reach a workload with access to secrets?

## Before you start

- An ARMO account you can sign in to at [cloud.armosec.io](https://cloud.armosec.io).
- An MCP-capable assistant. Setup for the common ones is below.
- Your region's server URL:

| Your ARMO login | Server URL |
|---|---|
| `cloud.armosec.io` | `https://api.armosec.io/mcp` |
| `cloud.us.armosec.io` | `https://api.us.armosec.io/mcp` |

There is nothing else to configure. No client ID, no client secret, and no callback
address to arrange in advance: your assistant registers itself with ARMO's sign-in the
first time it connects. The examples below use the EU URL. Substitute the US one if
that is where you sign in.

## Connect

Each section below says how far it has been checked. "Tested" means someone connected
that client to ARMO and ran a tool. "Checked against the vendor's documentation" means
the settings are right but nobody has run the flow end to end. If you try one of the
latter, tell us what you saw and we will mark it.


### Claude Code

*Tested.*

```bash
claude mcp add --transport http armo https://api.armosec.io/mcp
```

Then start `claude` and run `/mcp`. It will open a browser for you to sign in.

### ChatGPT

*Tested on 2026-10-20 against ARMO's development environment, from a Free ChatGPT
plan, by following these steps with the development server URL in step 2. The
production URLs below advertise the same sign-in settings, but nobody has connected
ChatGPT to them yet, so treat those as checked against configuration only.*

1. In ChatGPT, open **Plugins**, click **Add**, then **Add custom MCP server**.
2. Enter a name, such as `ARMO`, and your region's server URL from the table in
   "Before you start", for example `https://api.armosec.io/mcp`.
3. Leave **Authentication** on **OAuth**. If you open **Advanced OAuth settings**, you
   will see that ChatGPT has filled in ARMO's endpoints and chosen **Dynamic Client
   Registration (DCR)**. Leave that as it is.
4. Tick **I understand and want to continue** and click **Create as a plugin**.
5. Click **Connect** and sign in to ARMO in the page that opens.

To use it, open the plugin and click **Try in chat**, which starts a chat with ARMO
attached.

You do not need to turn on Developer mode first; the **Add** menu offered the option
directly on the plan we tested. We have not checked Business or Enterprise
workspaces, where an admin may control who can add custom servers.

Keep DCR. **Client Identifier Metadata Document (CIMD)** shows as unavailable, which is
expected because ARMO's sign-in does not support it. **User-Defined OAuth Client** is
only for the case where ARMO support has given you a client ID.

### Claude Desktop and Claude on the web

*Checked against Claude's documentation; not yet run end to end.*

Remote connectors are set up once in your Claude account and used by both.

1. Go to **Customize > Connectors**.
2. Click **+ Add**, then **Add custom connector**.
3. Enter a name, such as `ARMO`.
4. Enter `https://api.armosec.io/mcp` and click **Continue**.
5. Review the detected authentication settings and click **Continue**.
6. Under **Authentication**, choose **Sign in now**.
7. Under **OAuth client**, choose **Register automatically**.
8. Click **Add**, then **Connect**, and sign in to ARMO in the browser window.

Step 7 matters. **Use Claude's published identity** will not work: it relies on a
client identity document that ARMO's sign-in does not accept. **Register
automatically** is the option that matches how ARMO works.

On **Team and Enterprise** plans an Owner adds the connector once for everyone, under
**Organization settings > Connectors**: **Add**, hover **Custom**, choose **Web**, then
the same name, URL and options. Members then open **Customize > Connectors** and click
**Connect**.

### Cursor

*Schema checked against Cursor's documentation; not yet run end to end.*

Add the server to your MCP settings:

```json
{
  "mcpServers": {
    "armo": {
      "url": "https://api.armosec.io/mcp"
    }
  }
}
```

Cursor prompts you to sign in the first time a tool runs.

### VS Code

*Schema checked against the VS Code documentation; not yet run end to end.*

Open the Command Palette, run **MCP: Add Server**, choose **HTTP**, and enter
`https://api.armosec.io/mcp`.

To commit the setting with a project, put it in `.vscode/mcp.json`:

```json
{
  "servers": {
    "armo": {
      "type": "http",
      "url": "https://api.armosec.io/mcp"
    }
  }
}
```

### Any other MCP client

Point it at `https://api.armosec.io/mcp` over Streamable HTTP. Authentication is
standard OAuth 2.1.

The URL alone is enough for a client that supports dynamic client registration. Being
MCP-compliant does not imply that it does. ARMO advertises its registration endpoint
both in the RFC 8414 metadata at `/.well-known/oauth-authorization-server` and in the
OpenID Connect document at `/.well-known/openid-configuration`, so the client finds it
whichever of the two it reads.

If your client cannot register itself, it needs an OAuth client ID entered by hand.
Ask ARMO support for the one for your region; there is no client secret.

## What it can access

Thirteen tools, all read-only, all scoped to the ARMO accounts you belong to.

| Tool | What it returns |
|---|---|
| `query_vulnerabilities` | CVE findings, filterable by severity, CVE, in-use, exploitable and workload scope (cluster, namespace, workload, kind) |
| `query_workload_vulnerabilities` | the CVEs of each workload, one row per workload and CVE, with the same CVE filters; with `cve` set, only the workloads that have that CVE |
| `query_images` | container images with vulnerability rollups |
| `query_posture` | Kubernetes posture controls, filterable by framework |
| `query_cloud_posture` | cloud misconfiguration controls (CSPM) |
| `query_cloud_compliance` | cloud compliance framework scores |
| `list_cloud_accounts` | connected cloud accounts with posture rollups |
| `query_incidents` | runtime incidents, filterable by severity |
| `query_risks` | security risks, filterable by severity |
| `query_attack_chains` | attack paths toward sensitive assets |
| `list_inventory` | workloads and cloud resources |
| `list_repositories` | connected repositories with IaC posture |
| `list_accounts` | the ARMO accounts you can query, by name and GUID |

All the data tools support paging and field selection, so your assistant can request a
narrow slice instead of pulling everything. Each result names the account it came from,
by name and GUID.

## How access works

**You sign in as yourself.** The connection carries your identity and your role, not a
shared key. You see what you would see in the dashboard, and your colleagues see
theirs.

**Sessions are short.** A session lasts about an hour, after which your assistant asks
you to sign in again.

**Several accounts, one connection.** If your login has access to several ARMO accounts,
ask your assistant which accounts you have, or name one in the question ("show critical
CVEs in Acme"). Every data tool takes an optional `account`, either the account's name
or its GUID. Without it, the tool uses the account you were signed in to when you
authorised. Your role is checked separately in each account, so a read-only role in one
account stays read-only there even if you are an admin elsewhere.

The list of accounts is fixed when you sign in. If you are added to an account
afterwards, sign in to the connector again to use it.

**Nothing can be written.** The thirteen tools above are the entire surface. The server
cannot reach any other part of the ARMO API, and that limit is enforced by ARMO's
backend rather than by the assistant.

## Troubleshooting

**"Incompatible auth server: does not support dynamic client registration".**
Your assistant could not register itself. Three different causes produce this one
message, and only the first is yours:

- Your client does not support dynamic client registration. See "Any other MCP
  client" above.
- Registration is switched off for your region on ARMO's side.
- Discovery did not reach ARMO at all, for example through a proxy that blocks it.

Ask ARMO support either way. They can tell which of the three it is, and give you an
OAuth client ID to enter by hand, which works regardless of the cause.

**"Redirect uri wasn't found" when signing in.**
Your assistant registered a callback address ARMO did not accept. This should not
happen, because registration supplies the address. Contact ARMO support with the port
your client used.

**The assistant connects but every query comes back empty.**
Check you are using the URL for your region. An account in the US region does not
exist on the EU endpoint, so queries succeed and return nothing.

**Claude Desktop cannot reach the server.**
Custom connectors are reached from Anthropic's cloud, not from your machine, so the
URL has to be reachable from the public internet. If your ARMO instance sits behind a
VPN or an allow-list, Claude Code on your own machine works where Claude Desktop will
not.

**Sign-in succeeds but tools fail.**
Your ARMO role may not permit the data you are asking for. Read-only accounts can read
everything these tools expose, so this usually means the account is not in the
organisation you expect.

## Support

Problems with the connector or the data it returns: contact ARMO support, or open an
issue in this repository. To report a security issue, see [SECURITY.md](../SECURITY.md).

Running or deploying the server yourself: see [configuration.md](configuration.md).
