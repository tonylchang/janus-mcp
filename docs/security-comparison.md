# Security comparison

This matrix is a positioning aid, not a vulnerability assessment. It compares
the operational shape of Janus with common Kubernetes MCP server patterns as of
2026-06-14. Always verify current upstream behavior before making procurement
or production-risk decisions.

## Projects considered

- Janus: <https://github.com/tonylchang/janus-mcp>
- containers/kubernetes-mcp-server: <https://github.com/containers/kubernetes-mcp-server>
- Flux159/mcp-server-kubernetes: <https://github.com/Flux159/mcp-server-kubernetes>
- rohitg00/kubectl-mcp-server: <https://github.com/rohitg00/kubectl-mcp-server>
- alexei-led/k8s-mcp-server: <https://github.com/alexei-led/k8s-mcp-server>
- feiskyer/mcp-kubernetes-server: <https://github.com/feiskyer/mcp-kubernetes-server>

## Capability shape

| Dimension | Janus | Broad Kubernetes MCP servers |
|---|---|---|
| Primary job | Secure diagnostics plus bounded remediation | Natural-language kubectl/control-plane replacement |
| Tool count | Small, curated | Often broad: generic CRUD, Helm, exec, dashboards, ecosystem tools |
| Kubernetes access path | In-process Python Kubernetes client only | Often kubectl/helm wrappers, generic clients, or both |
| Generic command execution | No | Common in CLI-wrapper servers |
| Generic apply/patch/delete | No | Common |
| Exec/attach/port-forward/cp | No | Common in broad operator-style servers |
| Multi-cluster switching | Pinned context only | Often supported |
| Network transport | Local stdio only | Often stdio plus HTTP/SSE/streamable HTTP |

## Security controls

| Control | Janus stance | Why it matters |
|---|---|---|
| Kubeconfig exposure | Loaded in-process, pinned to one context, never serialized | Prevents the LLM context from receiving cluster credentials or API server URLs |
| Secret access | Credential-bearing kinds have no fetch registry entry | Avoids "fetch then redact" failure modes |
| Redaction | Structural per-kind rules, pattern/entropy scrub, byte-capped envelope | Treats adjacent leaks in env, annotations, ConfigMaps, logs, and events as expected |
| Redaction failure | Fail closed with a generic error | Prevents partially-redacted payloads from crossing MCP |
| Scope | Namespace allow/deny and cluster-scope opt-in on every call | Does not rely only on client behavior or kubeconfig RBAC |
| Writes | Registered only when enabled; human approval required at call time | A model-supplied parameter is never consent |
| Approval binding | SHA-256 of exact tool args; approval burned on use | Blocks approve-one-change/execute-another bait-and-switch |
| API abuse limits | Per-tool and global token buckets, timeouts, output caps | Bounds exfiltration bandwidth and cluster pressure |
| Leak regression tests | Full JSON-RPC frame capture greps canaries and kubeconfig markers | Makes credential non-exposure a CI contract |

## When to choose Janus

Choose Janus when the model is outside your trust boundary and the priority is
to let it diagnose Kubernetes safely: cluster credentials stay local, Secrets
are unreachable by construction, and any remediation is narrow enough for a
human to approve from a compact live-state card.

## When a broader server may fit better

Use a broader Kubernetes MCP server when you explicitly want the assistant to be
a general operator interface: installing charts, creating resources from
manifests, opening port-forwards, running exec sessions, or managing a fleet of
clusters through one MCP endpoint. Those are valid use cases, but they are a
different risk model from Janus.
