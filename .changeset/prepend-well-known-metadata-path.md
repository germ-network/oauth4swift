---
"@germ-network/oauth4swift": patch
---

Fix `.well-known` discovery URL construction for Protected Resource Metadata
(RFC 9728 §3.1) and Authorization Server Metadata (RFC 8414 §3.1). Both
`resourceDiscoveryRequest(url:)` and `authServerDiscovery(endpoint:)` now insert
`.well-known/oauth-protected-resource` / `.well-known/oauth-authorization-server`
**between the host and any existing path**, preserving the original path's
percent-encoding, port, and query, instead of appending it. Discovery against
resource identifiers or issuer URLs that carry a path (e.g.
`https://api.example.com/xrpc`) now hits the RFC-compliant metadata endpoint
and no longer silently 404s.
