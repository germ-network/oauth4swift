---
"@germ-network/oauth4swift": patch
---

Follow-ups to the `.well-known` discovery URL fix:

- `resourceDiscoveryRequest`/`authServerDiscovery` now validate that the
  discovered `resource`/`issuer` claim matches the requested identifier
  (RFC 9728 §3.3 / RFC 8414 §3.3), throwing `discoveredResourceMismatch` /
  `discoveredIssuerMismatch` otherwise.
- `insertingWellKnownSegment` now rejects (rather than silently normalizes)
  identifiers carrying userinfo, a query, a fragment, or a `.`/`..`/empty path
  segment, throwing `invalidResourceIdentifier`. A missing host now throws the
  more specific `missingHost` instead of `missingScheme`.
- A 404 at the RFC-compliant location now retries once at the pre-fix
  "append" location before reporting no metadata, for authorization/resource
  servers that only serve the legacy path.
- The helper and its `.well-known` suffix constants are now public, and moved
  to `URL+WellKnownDiscovery.swift` alongside the package's other `URL`
  extensions.
