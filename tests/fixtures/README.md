# These "credentials" are canaries, not leaks

Every secret-shaped string in this directory (`AKIA…`, `ghp_…`, JWTs,
passwords, connection strings) is a deliberately planted **canary** defined in
`tests/support.py`. None of them are, or ever were, real.

They exist so the test suite can prove the redaction pipeline works: the
security tests (`tests/security/`) drive a full MCP session over these
fixtures, record every JSON-RPC frame, and **fail the build** if any canary
crosses the boundary to the model.

If your secret scanner flagged this directory: working as intended. The
allowlist lives in `.gitleaks.toml`.
