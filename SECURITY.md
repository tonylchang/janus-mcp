# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** via GitHub's
[private vulnerability reporting](https://github.com/tonylchang/janus-mcp/security/advisories/new)
(Security tab → "Report a vulnerability"). Do not open a public issue for
anything that could expose cluster credentials or Secret material.

You can expect an acknowledgement within a week. Please include a minimal
reproduction; a failing test in the style of `tests/security/` is the gold
standard.

## What counts as a vulnerability here

janus-mcp's security contract is the five invariants in
[docs/threat-model.md](docs/threat-model.md). Any violation is a vulnerability,
most importantly:

- any way to make credential material (kubeconfig fields, tokens, certs) or
  `Secret` contents cross the MCP boundary;
- any redaction bypass that lets a planted canary-style credential reach the
  model (log lines, event messages, annotations, env values, …);
- any path that mutates the cluster without out-of-model human approval,
  including approval bait-and-switch;
- any server-side scope bypass (namespace allow/deny, cluster-scope gating).

Prompt-injection *content* in workload output is by design treated as inert
data — a hostile log line is only a vulnerability if it causes one of the
above without a human approving it.

## Supported versions

Pre-1.0: only the latest release receives fixes.
