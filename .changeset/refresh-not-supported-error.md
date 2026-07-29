---
"@germ-network/oauth4swift": patch
---

Add `OAuth.Errors.refreshNotSupported`

Thrown by the refresh gate when the server's `grant_types_supported` excludes
`refresh_token`, so the session is preserved (skip) rather than terminated, and
callers can distinguish "this server can never refresh - plan around
access-token expiry" from a transient failure. Note: adding a case to a public
enum breaks exhaustive switches over `OAuth.Errors`; no known consumer has one.
