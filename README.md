<h1 align="center">ARMO MCP server</h1>

<p align="center">
Ask your AI assistant about your ARMO security data, in plain language.
</p>

<p align="center">
  <a href="https://github.com/armosec/armo-mcp/actions/workflows/ci.yaml"><img alt="CI" src="https://github.com/armosec/armo-mcp/actions/workflows/ci.yaml/badge.svg"></a>
  <a href="https://goreportcard.com/report/github.com/armosec/armo-mcp"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/armosec/armo-mcp"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/github/license/armosec/armo-mcp"></a>
  <a href="https://hub.armosec.io"><img alt="Docs" src="https://img.shields.io/badge/docs-hub.armosec.io-blue"></a>
</p>

<p align="center">
  <a href="https://insiders.vscode.dev/redirect/mcp/install?name=armo&config=%7B%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A%2F%2Fapi.armosec.io%2Fmcp%22%7D"><img alt="Install in VS Code" src="https://img.shields.io/badge/VS_Code-Install_ARMO-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white"></a>
  <a href="https://cursor.com/en/install-mcp?name=armo&config=eyJ1cmwiOiJodHRwczovL2FwaS5hcm1vc2VjLmlvL21jcCJ9"><img alt="Add to Cursor" src="https://img.shields.io/badge/Cursor-Add_ARMO-000000?style=flat-square&logo=cursor&logoColor=white"></a>
</p>

The ARMO MCP server connects Claude, ChatGPT, Cursor, VS Code and any other
[Model Context Protocol](https://modelcontextprotocol.io) client to your
[ARMO](https://www.armosec.io) account. It answers questions about your vulnerabilities,
Kubernetes and cloud posture, runtime incidents and attack paths. Every answer comes
from your own data, with your own permissions.

ARMO runs the server, so there is nothing to install. Point your assistant at a URL and
sign in with your ARMO account.

```bash
claude mcp add --transport http armo https://api.armosec.io/mcp
```

If you sign in at `cloud.us.armosec.io`, use `https://api.us.armosec.io/mcp` instead.

## What you can ask

**Vulnerabilities**
> Which of my images have critical CVEs with a fix available?

> Show exploitable vulnerabilities in workloads that are actually loading the vulnerable package.

**Kubernetes posture**
> Which controls is my production cluster failing against NSA-CISA?

**Cloud posture**
> Are any of my AWS accounts failing CIS benchmarks? Which checks fail most often?

**Runtime**
> Show me runtime incidents from the last day and the workloads they touched.

**Attack paths and inventory**
> What attack paths reach a workload that can read secrets?

> List the repositories we scan and their worst IaC findings.

If your login can see several ARMO accounts, name the one you mean ("show critical
CVEs in the staging account"), or ask "which ARMO accounts can I see?".

## Getting started

| You sign in at | Server URL |
|---|---|
| `cloud.armosec.io` | `https://api.armosec.io/mcp` |
| `cloud.us.armosec.io` | `https://api.us.armosec.io/mcp` |

Sign-in is standard OAuth 2.1. Your assistant registers itself the first time it
connects, so you don't need a client ID, a secret or an API key. The examples use the
EU URL.

<details>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add --transport http armo https://api.armosec.io/mcp
```

Start `claude` and run `/mcp`. A browser window opens for you to sign in.
</details>

<details>
<summary><b>Claude Desktop and claude.ai</b></summary>

1. Open **Customize > Connectors**, click **+ Add**, then **Add custom connector**.
2. Name it `ARMO` and enter `https://api.armosec.io/mcp`.
3. Under **OAuth client**, choose **Register automatically**. (**Use Claude's published
   identity** will not work with ARMO's sign-in.)
4. Click **Add**, then **Connect**, and sign in.

On Team and Enterprise plans an Owner can add the connector once for the whole
organization under **Organization settings > Connectors**.
</details>

<details>
<summary><b>ChatGPT</b></summary>

1. Open **Plugins**, click **Add**, then **Add custom MCP server**.
2. Name it `ARMO` and enter your region's server URL.
3. Leave authentication on **OAuth** with **Dynamic Client Registration**.
4. Click **Create as a plugin**, then **Connect**, and sign in.
</details>

<details>
<summary><b>VS Code</b></summary>

Use the install button above, or run **MCP: Add Server** from the Command Palette,
choose **HTTP** and enter the URL. To share it with a project, add
`.vscode/mcp.json`:

```json
{
  "servers": {
    "armo": { "type": "http", "url": "https://api.armosec.io/mcp" }
  }
}
```
</details>

<details>
<summary><b>Cursor</b></summary>

Use the install button above, or add this to your MCP settings:

```json
{
  "mcpServers": {
    "armo": { "url": "https://api.armosec.io/mcp" }
  }
}
```
</details>

<details>
<summary><b>Any other MCP client</b></summary>

Connect over Streamable HTTP to your region's URL. A client that supports dynamic
client registration needs nothing else. One that doesn't needs an OAuth client ID
entered by hand: ask ARMO support for your region's.
</details>

Step-by-step notes for each client, including what has been tested end to end, are in
[docs/connecting.md](docs/connecting.md).

## Tools

All thirteen tools are read-only queries. Data tools page their results, let the assistant
pick only the fields it needs, and take an optional `account`.

| Tool | Returns |
|---|---|
| `query_vulnerabilities` | CVE findings, filtered by severity, CVE, in use, exploitable, cluster, namespace or workload |
| `query_workload_vulnerabilities` | the CVEs of each workload, one row per workload and CVE, paged over workloads |
| `query_images` | container images with vulnerability counts |
| `query_posture` | Kubernetes posture controls, by framework |
| `query_cloud_posture` | cloud misconfiguration findings (CSPM) |
| `query_cloud_compliance` | cloud compliance framework scores |
| `list_cloud_accounts` | connected cloud accounts and their posture |
| `query_incidents` | runtime incidents, by severity |
| `query_risks` | prioritized security risks |
| `query_attack_chains` | attack paths toward sensitive assets |
| `list_inventory` | workloads and cloud resources |
| `list_repositories` | connected repositories and their IaC posture |
| `list_accounts` | the ARMO accounts you can query |

## Security and privacy

- You sign in as yourself. The assistant sees what your ARMO role lets you see in the
  dashboard, and nothing more. A colleague who connects sees their own view.
- The server has no write tools. It can't start a scan, change a setting or dismiss a
  finding.
- The server stores nothing about you. Query results sit in memory for at most 30
  seconds when you use an API key, and are not cached at all when you sign in with
  OAuth, so revoking your session takes effect immediately.
- Sessions last about an hour, then your assistant asks you to sign in again.
- Your questions go to your AI provider, as with any MCP server. ARMO only sees the
  tool calls the assistant makes.

Found a vulnerability? Please report it privately, as described in
[SECURITY.md](SECURITY.md).

## Troubleshooting

**Queries succeed but return nothing.** Check that the URL matches your region. A US
account doesn't exist on the EU endpoint.

**"Does not support dynamic client registration".** Your client can't register itself.
Ask ARMO support for an OAuth client ID and enter it by hand.

**Claude Desktop can't reach the server.** Claude's connectors call the server from
Anthropic's cloud, so the URL must be reachable from the internet. Claude Code runs on
your machine and works behind a VPN.

More cases are covered in [docs/connecting.md](docs/connecting.md#troubleshooting).

## Running it yourself

ARMO hosts the server for you, but the code is here if you want to read it, run it
locally or contribute. It needs Go 1.26 or later.

```bash
make test     # unit tests
make build    # binary in ./bin
```

To query one account from a local build over stdio, with an access key:

```bash
export ARMO_CUSTOMER_GUID=<your-account-guid>
export ARMO_ACCESS_KEY=<your-access-key>
go run ./cmd/armo-mcp --stdio
```

Every setting is an environment variable; see [docs/configuration.md](docs/configuration.md).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).
