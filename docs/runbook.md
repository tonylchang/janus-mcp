# Operator runbook

## Install

```bash
uv tool install janus-mcp-server        # or: pipx install janus-mcp-server
# from a checkout:
uv sync
```

## Set up least-privilege credentials (strongly recommended)

```bash
kubectl create namespace janus-mcp
kubectl apply -f rbac/janus-mcp-rbac.yaml          # edit namespaces first
# create a kubeconfig context bound to the janus-mcp ServiceAccount token,
# e.g. named limited-sa@prod-cluster
```

## Configure

```bash
mkdir -p ~/.config/janus-mcp
cp examples/config.yaml ~/.config/janus-mcp/config.yaml
$EDITOR ~/.config/janus-mcp/config.yaml   # context, namespaces, write_tools
```

The server refuses to start if the pinned `context` is missing from the
kubeconfig, if required read permissions are absent, or (with `--strict`) if
the credentials are over-privileged (can read Secrets).

## Register with an MCP client (example: Claude Desktop)

`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kubernetes": {
      "command": "uvx",
      "args": ["janus-mcp", "serve", "--config", "/Users/me/.config/janus-mcp/config.yaml"]
    }
  }
}
```

## Approving writes

With an elicitation-capable client, approval cards render natively — read the
live state line before clicking Approve.

With other clients the write returns `status=pending approval_id=<id>`:

```bash
janus-mcp approvals            # list pending requests
janus-mcp approve <id>         # approve one
```

Then tell the assistant to re-issue the call with the same arguments. Approvals
expire (2.5× `approval_timeout_seconds`) and are burned on first use.

## Audit

Every call is one JSONL record in `~/.local/state/janus-mcp/audit.jsonl`
(rotated at 10 MiB): timestamp, tool, identifier args, scope/approval
decisions, redaction counts. Bodies are never logged.

```bash
jq 'select(.event=="write_approved")' ~/.local/state/janus-mcp/audit.jsonl
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `cannot load kubeconfig context` at start | The pinned `context` doesn't exist; check `kubectl config get-contexts` |
| `missing permissions: list pods in …` | Apply/extend the rbac/ manifests for that namespace |
| over-privilege warning at start | You pointed it at an admin kubeconfig; create the dedicated ServiceAccount |
| `rate limit exceeded` tool errors | Expected back-pressure; raise `limits.rate_per_minute` deliberately if needed |
| `truncated=true` in results | Narrow with `label_selector` / `tail_lines` / `since_minutes`; raise `result_max_bytes` only with token budget in mind |
| writes missing from the client's tool list | `read_only: true`, or the tool isn't in `write_tools.enabled` |
| EKS/GKE/AKS: works in terminal, fails from Claude Desktop / VS Code | GUI hosts spawn the server with a minimal `PATH`, so the kubeconfig's `exec:` auth plugin (`aws`, `gke-gcloud-auth-plugin`, `kubelogin`) isn't found — use the plugin's absolute path in `users[].user.exec.command` |
| `[REDACTED:high-entropy]` over-firing on legit IDs | Raise `redaction.entropy_threshold` slightly (e.g. 4.8); never disable the pass |

## Development

```bash
uv sync
uv run pytest                          # unit + security suites (no cluster needed)
uv run pytest tests/security           # the probing + frame-capture leak tests
UPDATE_GOLDENS=1 uv run pytest tests/unit/test_goldens.py   # regen, then REVIEW the diff
uv run ruff check . && uv run ruff format --check . && uv run mypy
npx @modelcontextprotocol/inspector uv run janus-mcp serve --config <cfg>  # interactive
```

Integration tests against a real cluster (kind):

```bash
kind create cluster --name janus-test
JANUS_KIND_TEST=1 uv run pytest tests/integration -m integration
```
