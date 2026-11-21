---
"@germ-network/oauth4swift": minor
---

Rework metadata discovery to follow the specs literally and mirror oauth4webapi.

**Breaking:** discovery moves from `HTTPFetcher` methods to static functions
on `OAuth`:

```swift
// before
let auth = try await fetcher.authServerDiscovery(endpoint: issuer).unwrapped
let resource = try await fetcher.resourceDiscoveryRequest(url: url).unwrapped

// after
let auth = try await OAuth.discoverAuthorizationServer(issuer: issuer, fetcher: fetcher)
let resource = try await OAuth.discoverProtectedResource(resource: url, fetcher: fetcher)
```

Both helpers return non-optional metadata. A non-success response (including
a 404) now throws instead of returning `nil`. Underneath, they combine
request/process pairs that mirror oauth4webapi's names, which are public for
callers that want the raw response: `OAuth.discoveryRequest` /
`OAuth.processDiscoveryResponse` and `OAuth.resourceDiscoveryRequest` /
`OAuth.processResourceDiscoveryResponse`.

The public `URL.insertingWellKnownSegment(_:)`,
`URL.canonicalDiscoveryIdentifier()`, `URL.WellKnownDiscovery` and the
`OAuth.wellKnownProtectedResource` / `OAuth.wellKnownAuthorizationServer`
constants are removed.

Behaviour changes:

- New `algorithm: OAuth.DiscoveryAlgorithm` on `discoveryRequest`: `.oauth2`
  (RFC 8414, `/.well-known/oauth-authorization-server` inserted before the path)
  or `.oidc` (OpenID Connect Discovery, `/.well-known/openid-configuration`
  appended after the path, e.g. for Keycloak realms). It defaults to `.oauth2`,
  unlike oauth4webapi's `.oidc`, because atproto requires RFC 8414.
- The returned `issuer`/`resource` must now be identical to the expected
  identifier (RFC 8414 §3.3, RFC 9728 §3.3, OIDC Discovery §4.3). Host case,
  default ports and percent-encoding are no longer normalized away, and
  request URLs are built from the identifier exactly as given.
- The retry at the appended `<path>/.well-known/<suffix>` location is
  removed: no spec defines it.
- Protected resource identifiers keep a terminating path slash and may carry
  a query, as RFC 9728 §3.1 allows. Issuers still strip a terminating slash
  and reject a query.
- `.`/`..`/empty path segments are no longer rejected.
