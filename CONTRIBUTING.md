# Contributing to janus-mcp

Thanks for helping make Kubernetes + LLMs safer. A few ground rules keep that
promise credible.

## The security contract comes first

The five invariants in [docs/threat-model.md](docs/threat-model.md) are hard
constraints on every change. If a PR weakens one, it will not merge — the
interesting conversation is how to get the feature *within* them.

Two repo-wide rules that follow from the contract:

- **No canary may ever appear in anything the model sees.** The fixtures are
  deliberately laced with fake credentials (`tests/support.py:ALL_CANARIES`);
  `tests/security/test_frame_capture.py` greps every JSON-RPC frame for them.
  Never weaken that test.
- **Golden files are a security control.** If your change alters redaction
  output, regenerate with `UPDATE_GOLDENS=1 uv run pytest tests/unit/test_goldens.py`
  and review the diff in both directions: leaks *and* over-redaction
  (over-redaction silently destroys diagnostic value). Explain golden diffs in
  the PR description.

Found a vulnerability instead? Please follow [SECURITY.md](SECURITY.md) —
private reporting, not a public issue.

## Development setup

```bash
git clone https://github.com/tonylchang/janus-mcp && cd janus-mcp
uv sync                    # installs the package (editable) + dev deps
uv run pytest              # full suite: unit + security, no cluster needed
```

Before pushing:

```bash
uv run ruff check . && uv run ruff format .
uv run mypy
uv run pytest
```

CI runs all of the above on Python 3.12 and 3.13, plus an OSV dependency audit
and a full-history gitleaks scan. Optional integration tests against a real
[kind](https://kind.sigs.k8s.io/) cluster:

```bash
kind create cluster --name janus-test
JANUS_KIND_TEST=1 uv run pytest tests/integration -m integration
```

## Adding or changing tools

Follow the pipeline described in [CLAUDE.md](CLAUDE.md): schema-validated
params → ScopeGuard → rate limit → one `kube.py` method → redaction →
`_shape` → audit. Every new tool needs golden tests, an adversarial probe
test, and `ToolAnnotations`. New write tools go through the ApprovalGate.
`subprocess` is never imported, anywhere.

## PRs

- Keep commits focused; explain *why* in the message body.
- New behavior needs tests — for security behavior, both the positive case
  and the probe that proves the refusal happens with zero API calls.
- GitHub Actions in workflows stay pinned by commit SHA.
