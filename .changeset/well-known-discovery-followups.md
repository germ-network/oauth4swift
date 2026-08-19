---
"@germ-network/oauth4swift": minor
---

Follow-ups to the `.well-known` discovery URL fix:

- `resourceDiscoveryRequest`/`authServerDiscovery` now validate that the
  discovered `resource`/`issuer` claim matches the requested identifier
  (RFC 9728 §3.3 / RFC 8414 §3.3), throwing `discoveredResourceMismatch` /
  `discoveredIssuerMismatch` otherwise. The comparison canonicalizes both
  sides (lowercased scheme/host, default port removed, path percent-encoding
  and Unicode normalization made consistent) so equivalent identifiers that
  differ only superficially — host case, an explicit default port, hex-case
  in a percent-escape, or Unicode normalization form — aren't rejected as a
  mismatch.
- `insertingWellKnownSegment` now rejects (rather than silently normalizes)
  identifiers carrying userinfo, a query, a fragment, or a
  `.`/`..`/empty path segment — including a percent-encoded one (`%2e`) —
  throwing `invalidResourceIdentifier`. A missing scheme now throws
  `missingScheme` and a missing host throws `missingHost`, distinctly.
- A 404 at the RFC-compliant location now retries once at the pre-fix
  "append" location before reporting no metadata, for authorization/resource
  servers that only serve the legacy path. Both URLs are now derived from a
  single parse of the source identifier.
- The helper and its `.well-known` suffix constants are now public, and moved
  to `URL+WellKnownDiscovery.swift` alongside the package's other `URL`
  extensions.

Known behavior changes from the pre-#61 baseline, kept as-is: a query string
on the identifier is now rejected rather than silently forwarded; an
identifier with more than one trailing slash is now rejected rather than
normalized; discovery may issue a second HTTP request (the legacy-location
retry) where it previously issued exactly one.
