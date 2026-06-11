# Quick start

Shortest path from zero to asking an AI assistant about your cluster, with the
credentials never leaving your machine.

## 1. Install

```bash
git clone https://github.com/tonylchang/janus-mcp && cd janus-mcp
uv sync
```

(Once published to PyPI, this becomes `uv tool install janus-mcp` and every
`uv --directory … run janus-mcp` below becomes just `uvx janus-mcp`.)

## 2. Configure

```bash
mkdir -p ~/.config/janus-mcp
cp examples/config.yaml ~/.config/janus-mcp/config.yaml
$EDITOR ~/.config/janus-mcp/config.yaml
```

You must set two things:

```yaml
context: my-context-name          # from `kubectl config get-contexts` — pinned, exact match
scope:
  allowed_namespaces: ["my-app"]  # namespaces that actually exist on that cluster
```

If your kubeconfig isn't at `~/.kube/config`, also set `kubeconfig: /path/to/file`.

Sanity-check before registering with any client:

```bash
uv run janus-mcp serve   # should print warnings (if any) and wait; Ctrl-C to stop
```

It refuses to start with a clear message if the context is missing or
permissions are absent. An "over-privileged credentials" warning means your
kubeconfig can read Secrets — janus-mcp never will, but see
[the runbook](runbook.md) for the least-privilege ServiceAccount setup.

## 3. Register with your MCP client

All recipes assume the checkout is at `~/git/janus-mcp`; adjust the path.
Client config formats change — when in doubt, check your client's MCP docs.

### Claude Code

```bash
claude mcp add kubernetes -- uv --directory ~/git/janus-mcp run janus-mcp serve
# or for all your projects:
claude mcp add --scope user kubernetes -- uv --directory ~/git/janus-mcp run janus-mcp serve
```

Start a new session and check `/mcp`. Note: Claude Code does not currently
render elicitation, so write approvals use `janus-mcp approve <id>` (see step 4).

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
`%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "kubernetes": {
      "command": "uv",
      "args": ["--directory", "/Users/me/git/janus-mcp", "run", "janus-mcp", "serve"]
    }
  }
}
```

Fully quit and reopen the app. Claude Desktop renders elicitation, so write
approvals appear as native cards.

### VS Code (GitHub Copilot agent mode)

`.vscode/mcp.json` in your workspace (or add via **MCP: Add Server** in the
command palette):

```json
{
  "servers": {
    "kubernetes": {
      "type": "stdio",
      "command": "uv",
      "args": ["--directory", "/Users/me/git/janus-mcp", "run", "janus-mcp", "serve"]
    }
  }
}
```

### Codex CLI

`~/.codex/config.toml`:

```toml
[mcp_servers.kubernetes]
command = "uv"
args = ["--directory", "/Users/me/git/janus-mcp", "run", "janus-mcp", "serve"]
```

### Cursor

`~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project):

```json
{
  "mcpServers": {
    "kubernetes": {
      "command": "uv",
      "args": ["--directory", "/Users/me/git/janus-mcp", "run", "janus-mcp", "serve"]
    }
  }
}
```

## 4. Use it

Ask things like:

> Why are pods crashing in the `prod` namespace?
> Summarize the health of my cluster.
> Show me the recent warning events for `payments-api`.

Clients that support MCP resources can also pin **`cluster://summary`** into
context (in Claude Code: type `@` and pick it) — a cached, sanitized one-screen
health overview the model gets for free, without spending a tool call.

For writes (if enabled in `write_tools.enabled`): the assistant *proposes*;
you approve. With elicitation-capable clients you get an approval card showing
live state. With others, the tool returns `status=pending approval_id=…`:

```bash
janus-mcp approvals          # see what's pending
janus-mcp approve <id>       # approve it
```

…then tell the assistant to retry the same call.

## 5. Managed clusters (EKS / GKE / AKS)

Nothing janus-specific to configure — auth is whatever your kubeconfig says,
including `exec:` credential plugins (`aws eks get-token`,
`gke-gcloud-auth-plugin`, `kubelogin`). One real gotcha: GUI-launched MCP
hosts (Claude Desktop, VS Code) spawn the server with a minimal `PATH`, so a
kubeconfig that says `command: aws` may fail with "executable not found" even
though it works in your terminal. Fix: use the **absolute path** to the plugin
binary in the kubeconfig's `users[].user.exec.command` field
(e.g. `/opt/homebrew/bin/aws`).

Cloud-targeting metadata (node provider IDs, external IPs, EKS/GKE/AKS labels,
IAM role annotations) is masked by the redaction engine by default.
