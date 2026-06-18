# Release security checklist

Security-first infrastructure tools are judged before they run. This checklist
keeps Janus releases aligned with the project threat model.

## Before cutting a release

- Run `uv run pytest`, including the security suite and frame-capture leak test.
- Run `uv run ruff check . && uv run ruff format --check . && uv run mypy`.
- Confirm the CI matrix passes on Python 3.12 and 3.13 and the built wheel
  succeeds in an isolated CLI smoke test.
- Confirm Gitleaks and OSV dependency scanning pass.
- If redaction behavior changed, regenerate goldens with `UPDATE_GOLDENS=1`,
  then review the diff for leaks and over-redaction before committing.
- Review the diff for new Kubernetes access paths. `kube.py` should remain the
  only module importing the Kubernetes client.
- Review the diff for any `subprocess`, generic patch/apply/delete, exec,
  attach, port-forward, cp, or shell-command behavior. These do not belong in
  Janus.
- Confirm every new tool has annotations with `openWorldHint: false`.
- Confirm every write is absent unless listed in `write_tools.enabled` and goes
  through `ApprovalGate`.

## Distribution targets

- Publish GitHub release artifacts with GitHub build provenance attestations.
- Attach an SPDX JSON SBOM to every GitHub release.
- Publish Python wheels and sdists with Trusted Publishing provenance.
- Publish a container image only after the image has an SBOM and vulnerability
  scan attached.
- Publish a Homebrew formula only after the release artifact checksums are
  generated from signed artifacts.

## Messaging alignment

- Confirm `README.md` and the PyPI-rendered project description tell the same
  story: security-first Kubernetes MCP gateway, credentials stay local,
  redacted diagnostics, scoped access, and bounded human-approved remediation.
- Confirm `pyproject.toml`'s `description` matches that positioning; it becomes
  the PyPI summary line.
- Confirm install snippets use the PyPI package name `janus-mcp-server` and the
  installed CLI name `janus-mcp` deliberately.
- Confirm the GitHub repository About text is consistent with the PyPI summary.
- Remove release-stale language that implies the package is not on PyPI before
  tagging.

## Public proof points

- Link the threat model from the README and release notes.
- Link `docs/security-comparison.md` from the README so users understand the
  difference between Janus and broad Kubernetes control-plane MCP servers.
- Mention the exact security tests run for the release, especially the
  frame-capture canary leak test.
- Call out new bounded remediation tools as named actions, not generic write
  capability.
