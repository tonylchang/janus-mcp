# Bounded remediation

Janus is diagnostics-first, but it is not diagnostics-only. The write surface is
deliberately small: each write is a named operational move with server-side
scope checks, a fresh Kubernetes read, rate limiting, explicit human approval,
and a shaped/redacted result. There is no generic apply, patch, delete, exec,
port-forward, cp, or shell command escape hatch.

## Current write tools

| Tool | Scope | Why it fits |
|---|---|---|
| `rollout_restart` | Deployment, StatefulSet, DaemonSet | Common remediation, no arbitrary spec edit, reason required |
| `scale_deployment` | Deployment, StatefulSet | Replica-only change, max replica policy, scale-to-zero opt-in |
| `pause_rollout` | Deployment | Single boolean change to stop a bad rollout while preserving state |
| `resume_rollout` | Deployment | Single boolean change to continue an already-paused rollout |

All write tools are absent from `tools/list` unless they are named in
`write_tools.enabled` and `read_only` is false.

## Good next candidates

These fit the Janus model because they are narrow, explainable, and can be
approved from a compact live-state card.

| Candidate | Type | Guardrails |
|---|---|---|
| `rollback_deployment` | Gated write | Deployment only; require explicit revision or previous revision; fetch ReplicaSets first; refuse ambiguous history; carry `resourceVersion`; show image/template diff in the approval card |
| `delete_controller_pod` | Gated write | Pod only; require ownerReferences with a controller owner; refuse naked/static/mirror pods; show owner and restart count; delete one pod by exact name |
| `restart_job_from_cronjob` | Gated write | CronJob only; create one Job with generated name; refuse arbitrary manifests; show schedule/suspend state |
| `cordon_node` / `uncordon_node` | Gated write | Require `allow_cluster_scoped`; exact node name; no drain; show Ready condition and unschedulable state |
| `clear_failed_job` | Gated write | Job only; require terminal failed/complete state; delete one Job by exact name; never delete Pods independently unless owned by that Job |

## Safe read-only expansions

These make Janus more useful without widening authority:

- `rollout_status` and `rollout_history`
- HPA target/current metric summary
- PVC binding and storage pressure summary
- image pull diagnosis
- probe failure diagnosis
- node pressure summary when cluster-scoped resources are enabled
- namespace health report that composes pods, events, deployments, HPAs, and PVCs

## Design rules

Every remediation tool should satisfy all of these before it ships:

- No generic YAML, JSON patch, kubectl, helm, exec, port-forward, cp, or shell-out.
- One Kubernetes method in `kube.py`; typed safe errors only.
- Validate names and numeric bounds before any API call.
- Scope-check before any API call.
- Fresh-read live state before approval.
- Approval card says exactly what will change and shows live state.
- Approval is out-of-model: MCP elicitation or the CLI approval store.
- Bind approval to the exact argument hash and burn it on use.
- Use `resourceVersion` or another Kubernetes precondition where the API supports it.
- Return a short redacted status, then let read tools observe the aftermath.
