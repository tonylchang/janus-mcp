# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Janus is

A local MCP server (Python 3.12+, official `mcp` SDK / FastMCP, stdio transport) that gives LLM clients scoped, redacted access to Kubernetes clusters. The kubeconfig is loaded in-process and pinned to one context; everything the model sees passes a redaction pipeline; writes require out-of-model human approval. `docs/threat-model.md` states the five security invariants — treat them as hard constraints on any change.

## Commands

```bash
uv sync                                   # install (editable) + dev deps
uv run pytest                             # full suite: unit + security (no cluster needed)
uv run pytest tests/security              # adversarial probes + frame-capture leak test
uv run pytest tests/unit/test_patterns.py -k jwt        # single test
UPDATE_GOLDENS=1 uv run pytest tests/unit/test_goldens.py  # regen goldens — REVIEW the diff, it's a security control
uv run ruff check . && uv run ruff format --check .     # lint/format (line length 100)
uv run mypy                               # strict, src/ only
uv run janus-mcp serve --config examples/config.yaml    # run server (needs a real kubeconfig context)
uv run janus-mcp approvals / approve <id> # out-of-band write approval CLI
JANUS_KIND_TEST=1 uv run pytest tests/integration -m integration  # needs `kind create cluster --name janus-test`
npx @modelcontextprotocol/inspector uv run janus-mcp serve --config <cfg>  # interactive protocol debugging
```

## Architecture

Every tool handler in `server.py` runs the same pipeline, in order:

```
validate (validation.py) → ScopeGuard → RateLimiter → kube call (kube.py)
  → structural redaction (redaction/structural.py, Layer 1)
  → pattern/entropy scrub (redaction/patterns.py, Layer 2)
  → envelope/byte-cap (redaction/render.py, Layer 3) → audit (audit.py)
```

- `kube.py` is the **only** module that imports the kubernetes client. It maps every exception to a typed, generic message — raw client errors embed the API server URL and must never reach the model. The kind registry there deliberately omits `Secret` & co.; that absence (not a filter) is invariant 2.
- `server.py:build_server(settings, kube, audit)` takes the kube layer as an injected `KubeApi` protocol — tests substitute `tests/support.py:FakeKube`. Write tools are only *registered* when enabled and not `read_only`; the `ApprovalGate` checks again at call time. The `cluster://summary` MCP resource shares the summary tool's cache and pipeline (`_summary_text`).
- `policy.py` holds ScopeGuard (deny wins), RateLimiter (token buckets), and ApprovalGate. Approval comes from MCP elicitation when the client supports it, else a file-based out-of-band store (`janus-mcp approve <id>`) that binds a SHA-256 of the exact args to the approval ID and burns it on use. A model-supplied "confirmed" parameter is never consent.
- Rendering failures fail **closed** (`_shape` in server.py): the model gets a generic error, never a partially-redacted payload.
- Config (`config.py`, pydantic strict) rejects unknown keys so typos in security-relevant settings fail at startup. The pinned `context` is required.

## Testing conventions

- `tests/support.py` defines the canary credentials (`ALL_CANARIES`) and `FakeKube`, which records calls so probes can assert "policy error fired with **zero** API calls". Fixtures in `tests/fixtures/` are deliberately laced with canaries.
- The repo-wide contract: **no canary may ever appear in anything the model sees.** `tests/security/test_frame_capture.py` records every JSON-RPC frame of a full session and greps for canaries and kubeconfig markers — this is the keystone test; never weaken it.
- Golden files (`tests/unit/goldens/`) are byte-for-byte pipeline outputs. When redaction rules change, regenerate with `UPDATE_GOLDENS=1` and review the diff for leaks *and* over-redaction (over-redaction silently destroys diagnostic value — negative cases matter as much as positive ones).
- Async tests use the anyio pytest plugin (`pytest.mark.anyio` + `anyio_backend` fixture), not pytest-asyncio. In-process client/server sessions come from `mcp.shared.memory.create_connected_server_and_client_session`; pass `elicitation_callback` to simulate approval UI. Note the client SDK processes incoming requests inline in its receive loop — a slow elicitation callback blocks the tool result delivery (keep test callbacks short).

## Adding a tool

Schema-validated params (+ explicit `validation.py` checks) → ScopeGuard call → rate limit → one `kube.py` method → redaction rules (extend `structural.py` if a new kind) → golden tests + a probe test → `ToolAnnotations` declared (`readOnlyHint`, `openWorldHint: false`). Output must be bounded and pass through `_shape`. No `subprocess`, ever. New write tools go through ApprovalGate and must be listed in `write_tools.enabled` to even register.
