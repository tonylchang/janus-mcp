# Threat model

## What janus-mcp protects

The asset is **cluster credential material and Secret contents**: the
kubeconfig (API server URL, CA data, client certs, bearer tokens), Kubernetes
`Secret` objects, and any secret values that leak into adjacent places (env
values, annotations, ConfigMaps, workload stdout). The adversary of record is
**the LLM's context window** — anything that crosses the MCP boundary may be
logged, retained, or exfiltrated by whatever is on the other side, so the only
winning move is to never put secrets there.

## Security invariants (enforced by construction, verified in CI)

1. **Credentials stay in server memory.** The kubeconfig is loaded in-process
   (`kube.py`, pinned context) and is never serialized into any MCP frame,
   tool description, log line, or error message. Verified by the frame-capture
   leak test (`tests/security/test_frame_capture.py`), which records every
   JSON-RPC frame of a full scripted session and greps for canaries and
   kubeconfig markers — zero hits or the build fails.
2. **Secrets are unreadable by design.** `Secret` (and `ServiceAccount`,
   `CertificateSigningRequest`, `TokenReview`) have no entry in the kind
   registry — the server never fetches them, so it cannot leak them.
   `describe_resource(kind=Secret)` returns a policy error with zero API calls.
3. **Everything model-visible passes redaction.** Three layers
   (`src/janus_mcp/redaction/`): structural per-kind field rules, pattern +
   entropy scrubbing of all free text, and output shaping with byte caps.
   Failures fail *closed* — a redaction exception returns a generic error,
   never the payload.
4. **Writes need out-of-model human approval.** A model-supplied parameter is
   never consent. Approval arrives via MCP elicitation (client-rendered UI) or
   the out-of-band CLI (`janus-mcp approve <id>`), which binds a SHA-256 hash
   of the exact arguments to the approval ID (bait-and-switch prevention) and
   burns each approval on first use.
5. **Scope is enforced server-side on every call**, independent of RBAC:
   namespace allow/deny lists (deny wins), cluster-scope opt-in, kubeconfig
   context pinning, and least-privilege RBAC manifests (`rbac/`) as the second
   independent layer.

## Attack surfaces and mitigations

| Vector | Mitigation |
|---|---|
| Reading `Secret` objects | No code path can fetch them (invariant 2) |
| `kubectl.kubernetes.io/last-applied-configuration` (embeds full prior object incl. env values) | Dropped unconditionally, never allowlistable |
| Env values / ConfigMap data / credential-bearing annotations | Structural masking; references (secretKeyRef etc.) shown by name only |
| Credentials echoed into logs/events by workloads | Pattern + entropy scrubber with typed replacement tokens |
| Prompt injection via log/event text | Writes always require human approval; untrusted-output framing; static tool descriptions; approval card shows live state + exact change, fetched at approval time |
| Approval bait-and-switch (approve A, execute B) | Argument-hash binding; burn-on-use; fresh-read `resourceVersion` carried in the patch, 409 on conflict |
| Secret-probing via `grep` match counts | grep filters *after* redaction |
| Error messages leaking the API server URL (urllib3 embeds it) | All client exceptions mapped to typed generic messages; details go to local stderr only |
| Enumeration via not-found errors | Names validated and scope-checked before any API call |
| Command injection | No shell-outs anywhere; the Kubernetes client library is the only egress; `subprocess` is never imported |
| Over-privileged kubeconfig | Startup `SelfSubjectAccessReview` probe warns loudly (refuses under `--strict`) if credentials can read Secrets; integration tests run as the restricted ServiceAccount |
| API server abuse / exfiltration bandwidth | Per-tool + global token buckets, request timeouts, result byte caps |

## Non-goals (v1)

No `exec`/`attach`/`port-forward`/`cp`; no Secret reads under any
circumstances; not a general kubectl replacement; single-operator local trust
domain (stdio transport, no network listener, no multi-tenant auth).

## Residual risks

- The entropy scrubber has false positives (long high-entropy identifiers) and
  false negatives (low-entropy secrets like dictionary passwords outside
  key=value shapes). Tune `redaction.entropy_threshold`; never disable the pass.
- Namespace and resource *names* in scope are visible to the model by design;
  if names themselves are sensitive, scope them out.
- A hostile workload can still spam misleading diagnostics (prompt injection);
  the payoff is capped at a human-read approval card, but human attention is
  the last line of defense — read the card.
