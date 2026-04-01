# @germ-network/oauth4swift

## 0.2.0

### Minor Changes

- [#13](https://github.com/germ-network/oauth4swift/pull/13) [`fab1414`](https://github.com/germ-network/oauth4swift/commit/fab141411927b00ed356ca9102e207c9593a5613) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Change signature for tokenValidator

  `tokenValidator` previously returned a `SessionState.Mutable` which leaked internal implementation details into the consuming code. Instead, `tokenValidator` now just asynchronously returns a `Bool` and the `SessionState.Mutable` is constructed in the `processAuthorizationCodeOAuth2Response` method and the private `refresh` method in `OAuthSessionCapabilities`.

  The `tokenValidator` also now receives an "immutable" copy of the previous `SessionState`, allowing clients to validate that for instance the `additionalParams` on a token haven't changed during refresh. When `tokenValidator` is called from `processAuthorizationCodeOAuth2Response`, the previous `SessionState` is nil, since we don't have a previous session.

- [#16](https://github.com/germ-network/oauth4swift/pull/16) [`daf14a5`](https://github.com/germ-network/oauth4swift/commit/daf14a56914b5b98e8c67b3406545af77e0241f7) Thanks [@germ-mark](https://github.com/germ-mark)! - adopt swift-http-types via GermConvenience

  add typed HTTPField.Name(s) for DPoP and DPoP-Nonce

### Patch Changes

- [#13](https://github.com/germ-network/oauth4swift/pull/13) [`c8cd10f`](https://github.com/germ-network/oauth4swift/commit/c8cd10ffe48c1cbe7a16d9cc07e8b5fb8766a8b2) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Store OAuth Client in SessionState

- [#15](https://github.com/germ-network/oauth4swift/pull/15) [`3e82534`](https://github.com/germ-network/oauth4swift/commit/3e82534d87a072fd5ecf4dcd3f5b5ec919581a49) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Fix handling of missing scope in token response

- [#13](https://github.com/germ-network/oauth4swift/pull/13) [`e7ba1d0`](https://github.com/germ-network/oauth4swift/commit/e7ba1d09872a724ac8dd700f29757fc7a517d845) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Add support for draft-ietf-oauth-refresh-token-expiration

  The new [draft-ietf-oauth-refresh-token-expiration](https://drafts.oauth.net/rt-expiration/draft-ietf-oauth-refresh-token-expiration.html) from the OAuth WG at IETF allows for Authorization Servers to signal to clients when:

  - the Authorization Grant expires
  - the Refresh Token expires

  This allows a client to know that the refresh token isn't even valid anymore, before attempting to do a token refresh.

## 0.1.0

### Minor Changes

- [#11](https://github.com/germ-network/oauth4swift/pull/11) [`0de45c7`](https://github.com/germ-network/oauth4swift/commit/0de45c752a7a043ac1589831f56b88625fe28b86) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Rename parameters for consistency

  The following parameters were renamed:

  - `redirectURL` to `redirectURI`
  - `callbackURL` is now `redirectURI` in `OAuthClient` (the replacement for `AppCredentials`)
  - `func finishAuthorization` and `func validateAuthResponse` now take a `callbackURL` parameter instead of `redirectURI`
  - `func validateAuthResponse` now can also take just the parameters from the `callbackURL` via `callbackParameters` instead, this is an array of `URLQueryItem`
  - `func validateAuthResponse` now returns a branded type `AuthResponseParameters` instead of a `ParsedRedirect`. This is the `callbackParameters` passed to `authorizationCodeGrantRequest`, which has a subscript to get the values for an individual query parameter, e.g, `callbackParameters["code"].first`
  - `func authorizationCodeGrantRequest` now accepts a `redirectURI: URL` and `callbackParameters: AuthResponseParameters` parameters instead of `redirectUrl` and `parsedRedirect`
  - `func validateAuthResponse` now takes a `callbackURL` parameter instead of `redirectURL` and `expectedState` is now an optional string, allowing for usage against OAuth 2.0 servers, where the `state` parameter is not required. (`AuthorizeInputs` still generates a `state` parameter value by default, and this isn't optional)

- [#11](https://github.com/germ-network/oauth4swift/pull/11) [`0de45c7`](https://github.com/germ-network/oauth4swift/commit/0de45c752a7a043ac1589831f56b88625fe28b86) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Rename AppCredentials to OAuthClient

  - `AppCredentials` struct is renamed to `OAuthClient`
  - `appCredentials` as a parameter has been renamed to `clientMetadata`

### Patch Changes

- [#11](https://github.com/germ-network/oauth4swift/pull/11) [`0de45c7`](https://github.com/germ-network/oauth4swift/commit/0de45c752a7a043ac1589831f56b88625fe28b86) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Support AuthorizeInput scopes being different from OAuthClient scopes

- [#11](https://github.com/germ-network/oauth4swift/pull/11) [`0de45c7`](https://github.com/germ-network/oauth4swift/commit/0de45c752a7a043ac1589831f56b88625fe28b86) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Improve error handling in `validateAuthResponse`

  When we receive an `error` parameter back from the `userAuthenticator` (e.g., the user denies the authorization request), `validateAuthResponse` will now throw more specific errors than just `OAuthError.redirectError`. The following more specific errors are supported:

  - `OAuthError.accessDenied` for when the user denies the authorization grant
  - `OAuthError.invalidRequest` if the authorization request was malformed
  - `OAuthError.invalidScope` if the scope requested was invalid

  Whilst there are [more expected OAuth Errors](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1), the other errors are throw as `OAuthError.redirectError(error, errorDescription?)`. The `error` parameter to the `OAuthError.redirectError` is always forced to lowercase, per specification.

  We don't currently support `error_uri`, only `error` and `error_description`.

- [#11](https://github.com/germ-network/oauth4swift/pull/11) [`0de45c7`](https://github.com/germ-network/oauth4swift/commit/0de45c752a7a043ac1589831f56b88625fe28b86) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Fix missing Authorization header for DPoP Requests

## Earlier than 0.1.0

We had two earlier tags for `0.0.1` and `0.0.2` prior to having release tooling in place.
