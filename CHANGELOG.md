# @germ-network/oauth4swift

## 0.1.0

### Minor Changes

- [#7](https://github.com/germ-network/oauth4swift/pull/7) [`b857d8a`](https://github.com/germ-network/oauth4swift/commit/b857d8adee04ac0e87f4fbb25ccc1083059a8109) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Rename parameters for consistency

  The following parameters were renamed:

  - `redirectURL` to `redirectURI`
  - `callbackURL` is now `redirectURI` in `OAuthClient` (the replacement for `AppCredentials`)
  - `func finishAuthorization` and `func validateAuthResponse` now take a `callbackURL` parameter instead of `redirectURI`
  - `func validateAuthResponse` now can also take just the parameters from the `callbackURL` via `callbackParameters` instead, this is an array of `URLQueryItem`
  - `func validateAuthResponse` now returns a branded type `AuthResponseParameters` instead of a `ParsedRedirect`. This is the `callbackParameters` passed to `authorizationCodeGrantRequest`, which has a subscript to get the values for an individual query parameter, e.g, `callbackParameters["code"].first`
  - `func authorizationCodeGrantRequest` now accepts a `redirectURI: URL` and `callbackParameters: AuthResponseParameters` parameters instead of `redirectUrl` and `parsedRedirect`
  - `func validateAuthResponse` now takes a `callbackURL` parameter instead of `redirectURL` and `expectedState` is now an optional string, allowing for usage against OAuth 2.0 servers, where the `state` parameter is not required. (`AuthorizeInputs` still generates a `state` parameter value by default, and this isn't optional)

- [#7](https://github.com/germ-network/oauth4swift/pull/7) [`b857d8a`](https://github.com/germ-network/oauth4swift/commit/b857d8adee04ac0e87f4fbb25ccc1083059a8109) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Rename AppCredentials to OAuthClient

  - `AppCredentials` struct is renamed to `OAuthClient`
  - `appCredentials` as a parameter has been renamed to `clientMetadata`

### Patch Changes

- [#7](https://github.com/germ-network/oauth4swift/pull/7) [`b857d8a`](https://github.com/germ-network/oauth4swift/commit/b857d8adee04ac0e87f4fbb25ccc1083059a8109) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Support AuthorizeInput scopes being different from OAuthClient scopes

- [#7](https://github.com/germ-network/oauth4swift/pull/7) [`b857d8a`](https://github.com/germ-network/oauth4swift/commit/b857d8adee04ac0e87f4fbb25ccc1083059a8109) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Improve error handling in `validateAuthResponse`

  When we receive an `error` parameter back from the `userAuthenticator` (e.g., the user denies the authorization request), `validateAuthResponse` will now throw more specific errors than just `OAuthError.redirectError`. The following more specific errors are supported:

  - `OAuthError.accessDenied` for when the user denies the authorization grant
  - `OAuthError.invalidRequest` if the authorization request was malformed
  - `OAuthError.invalidScope` if the scope requested was invalid

  Whilst there are [more expected OAuth Errors](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1), the other errors are throw as `OAuthError.redirectError(error, errorDescription?)`. The `error` parameter to the `OAuthError.redirectError` is always forced to lowercase, per specification.

  We don't currently support `error_uri`, only `error` and `error_description`.

- [#7](https://github.com/germ-network/oauth4swift/pull/7) [`b857d8a`](https://github.com/germ-network/oauth4swift/commit/b857d8adee04ac0e87f4fbb25ccc1083059a8109) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Fix missing Authorization header for DPoP Requests
