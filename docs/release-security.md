# Release security checklist

Security-first infrastructure tools are judged before they run. This checklist
keeps Janus releases aligned with the project threat model.

## Before cutting a release

- Run `uv run pytest`, including the security suite and frame-capture leak test.
- Run `uv run ruff check . && uv run ruff format --check . && uv run mypy`.
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

- Publish signed GitHub release artifacts.
- Publish Python wheels and sdists with provenance once the release pipeline
  supports it.
- Publish a container image only after the image has an SBOM and vulnerability
  scan attached.
- Publish a Homebrew formula only after the release artifact checksums are
  generated from signed artifacts.

## Public proof points

- Link the threat model from the README and release notes.
- Link `docs/security-comparison.md` from the README so users understand the
  difference between Janus and broad Kubernetes control-plane MCP servers.
- Mention the exact security tests run for the release, especially the
  frame-capture canary leak test.
- Call out new bounded remediation tools as named actions, not generic write
  capability.
