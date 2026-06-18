# Streamable HTTP transport: security gates

Janus does not currently expose a network listener. Stdio keeps the v1 trust
domain deliberately small: one local operator, one client process, and local
state owned by the same OS account. Streamable HTTP is deferred until the
controls below are implemented and verified as a separate security boundary.

## New attack surface

- Remote or cross-origin callers can discover and invoke tools.
- Browser clients introduce DNS rebinding, CSRF, and hostile `Origin` values.
- Long-lived sessions introduce fixation, replay, resource exhaustion, and
  cross-session result delivery risks.
- Multiple users make local file approvals ambiguous: an approval must be bound
  to an authenticated principal and server session, not only tool arguments.
- Proxies can change the apparent client address, scheme, host, and TLS state.

## Required controls before release

1. Bind to loopback by default. Non-loopback binds require an explicit unsafe
   acknowledgement and documented TLS-terminating reverse proxy.
2. Require a high-entropy bearer token sourced from a protected file or process
   environment. Never accept it in a URL or config committed to the repository.
3. Validate `Origin` against an exact allowlist and reject missing origins for
   browser-shaped requests. Validate `Host` to resist DNS rebinding.
4. Give every connection an authenticated principal and unguessable session ID.
   Never share resources, pending approvals, caches, or responses across them.
5. Bind approval records to principal, session, tool arguments, resource UID,
   and `resourceVersion`. Elicitation responses must return to the requesting
   session; out-of-band approval must display the principal and session.
6. Apply request-body, header, connection, session, and response-size limits in
   addition to the existing per-tool rate limits and Kubernetes timeouts.
7. Disable CORS credentials and wildcard origins. Reject proxy-forwarded headers
   unless the proxy address is explicitly trusted.
8. Emit security audit events for authentication failures, origin rejection,
   session creation/expiry, rate limiting, and approval decisions without
   logging bearer tokens or request bodies.

## Verification gate

HTTP support needs frame-capture equivalents for authentication bypass, Origin
and Host confusion, cross-session leakage, approval replay, stale state, slow
clients, oversized requests, disconnect cancellation, and concurrent sessions.
It must also pass the existing canary suite unchanged. Until those tests exist,
stdio remains the only supported transport.
