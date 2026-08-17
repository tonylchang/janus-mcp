# Changelog

All notable changes to janus-mcp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer
(0.x: minor bumps may include behavior changes).

## [Unreleased]

### Added

- **Read tools**:
  - `list_resources`: enumerate any allowlisted namespaced kind (Deployments,
    Services, CronJobs, PVCs, HPAs, Endpoints, quotas, …) with a per-kind
    status summary — the model no longer has to guess names from pod prefixes.
  - `get_resource_usage`: live per-pod CPU/memory from the metrics API joined
    with requests/limits from the pod spec (`kubectl top` plus headroom).
  - `get_rollout_status`: Deployment conditions, revision history with images
    and readiness, and a sanitized template diff of current vs previous
    revision — "what changed recently", with credentials masked on both sides.
- **Readable kinds**: Endpoints (node names masked per policy), ResourceQuota,
  LimitRange, PodDisruptionBudget.
- **Write tools** (approval-gated, disabled unless listed in
  `write_tools.enabled`, each bound to the state the approver saw):
  - `delete_pod` — kick a stuck pod; the delete carries a UID precondition so
    a same-name replacement pod aborts with a conflict. Pods without a
    controller owner are refused unless `write_tools.allow_bare_pod_deletion`.
  - `rollout_undo` — roll a Deployment back to its previous revision; the
    approval card shows the sanitized template diff, and the patch is bound to
    both the observed resourceVersion and the approved target revision.
  - `set_cronjob_suspend` / `trigger_cronjob` — pause/resume a schedule, or
    create a one-off Job from the CronJob's template (name derived
    server-side).
  - `cordon_node` / uncordon — requires `scope.allow_cluster_scoped`; no drain
    (evictions stay human-driven).
- RBAC manifests updated with per-tool grant comments; the new read grants,
  and optional metrics.k8s.io / node rules.
- `diagnose_namespace` MCP prompt: a structured triage playbook (overview →
  pods → warning events → targeted logs → synthesized diagnosis) for clients
  that support prompts. The prompt is a static template parameterized only by
  a validated, in-scope namespace — it performs no cluster reads itself, and
  scope refusals are audited like any other entry point.

## [0.2.0] — 2026-08-15

A security-hardening release. A deep review of the redaction pipeline, the
approval flow, and the policy layer found and fixed ten defects; all fixes
ship with regression tests, and the golden outputs are byte-identical except
where a fix required otherwise. Upgrading is strongly recommended.

### Security fixes

- **CronJob identity annotations leaked** (`describe_resource`):
  `spec.jobTemplate.metadata.annotations` (IAM role ARNs, workload-identity
  and Vault annotations) bypassed structural redaction — only the pod
  template inside it was filtered. Both metadata levels are now filtered.
- **Out-of-band approval bait-and-switch**: an approved `scale_deployment`
  retry patched with a `resourceVersion` read *after* approval, so a change
  made while the approval waited (an HPA, a colleague) was silently applied
  to state the operator never saw. OOB approvals now bind the
  `resourceVersion` observed when the request was created; a change since
  then aborts with a typed conflict.
- **Approval cards showed fabricated readiness**: the Scale subresource's
  `status.replicas` (a total) was presented as "N/N ready", so a fully
  crash-looping workload looked healthy to the approver. Cards now show real
  `readyReplicas` read from the object itself.
- **Masked-value oracle via field selectors**: `get_pods` forwarded
  model-supplied field selectors verbatim, so `spec.nodeName=<guess>`
  match/no-match confirmed node names that redaction masks. Field selectors
  are now allowlisted per tool (`metadata.name`, `status.phase`;
  `spec.nodeName` only when node masking is disabled).
- **Public IPv6 addresses were never masked** by the scrubber
  (IPv4-only regex). IPv6 candidates are now validated and masked, including
  IPv4-mapped forms.
- **Entropy scrubber was a mathematical no-op for common secret shapes**:
  hex tokens max out at 4 bits/char and 20-char tokens at log2(20), both
  below the 4.5 threshold — hex HMACs and short random tokens could never be
  caught. Thresholds now scale by charset and length; DNS-1123-shaped tokens
  (Kubernetes names), pure numbers, and `key=<short-id>` labels keep their
  diagnostic value.
- **Truncation dropped the closing untrusted-content fence** on large log
  output — exactly the attacker-controllable case the framing defends.
  The fence now survives truncation.
- **Elicitation failures could propagate raw errors**: a broken approval
  exchange now maps to a denial, never an exception toward the model.

### Fixed

- Dotted Node names (`ip-…​.us-west-2.compute.internal`, standard on
  EKS/GKE) were rejected by name validation; DNS-1123 subdomains are now
  accepted.
- A client retry-looping one rate-limited tool drained the shared global
  bucket and starved every other tool; per-tool denial no longer consumes
  global tokens.
- Cached `get_cluster_summary` / `cluster://summary` reads produced no audit
  record; cache hits now log with `cached=true`.
- `redaction.namespace_label_allowlist` was accepted by config but never
  applied; Namespace labels are now masked unless allowlisted.
- Approval pending/denied messages now pass through the same
  scrub-and-fail-closed shaping as every other model-visible string.

### Added

- Audit events: `refused` (scope and rate-limit denials — reconnaissance
  leaves a trace) and `write_executed` (recorded only after a mutation
  succeeded, distinguishing approved-but-failed from executed).
- `write_tools.oob_approval_ttl_seconds` (default 600): the out-of-band
  approval lifetime is its own setting instead of a hidden multiple of the
  elicitation timeout.
- A live kind-cluster integration test for the write path (real Scale
  subresource, readiness card, resourceVersion-bound patch).

### Changed

- **Behavior**: field selectors on `get_pods` are restricted to an allowlist
  (see security fixes); bare high-entropy hex identifiers ≥20 chars in logs
  (trace IDs, container IDs) are now masked as `[REDACTED:high-entropy]` —
  raise `redaction.entropy_threshold` if this over-triggers for you.
- Dependencies: locked versions upgraded past known CVEs in cryptography,
  mcp, pyasn1, pydantic-settings, and starlette; `mcp` is pinned to
  `>=1.28.1,<2` (2.x migration tracked in
  [#13](https://github.com/tonylchang/janus-mcp/issues/13)).

## [0.1.0] — 2026-06-11

Initial release: scoped, redacted read tools (`get_pods`, `get_events`,
`describe_resource`, `get_logs`, `list_namespaces`, `get_cluster_summary`,
`cluster://summary` resource) and human-approved write tools
(`rollout_restart`, `scale_deployment`) over stdio MCP.
