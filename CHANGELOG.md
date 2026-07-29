# @germ-network/oauth4swift

## 0.6.0

### Minor Changes

- [#48](https://github.com/germ-network/oauth4swift/pull/48) [`4458abe`](https://github.com/germ-network/oauth4swift/commit/4458abe55e058f84475d7eee92fdd03b2f97de0d) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Add `ClientAuth.Method` and `ClientAuth.SecretMethod` protocols; conform `None`, `SecretBasic`, and `SecretPost`

- [#48](https://github.com/germ-network/oauth4swift/pull/48) [`fc3addb`](https://github.com/germ-network/oauth4swift/commit/fc3addb88e553e30eeb8bc8cbad09206ce429411) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Add `revocationRequest` to `ClientAuth.Authenticable`; add `RevocableToken` enum with `token_type_hint` support (RFC 7009)

- [#48](https://github.com/germ-network/oauth4swift/pull/48) [`98faa4c`](https://github.com/germ-network/oauth4swift/commit/98faa4c6b95eeae649965f34273e886d882f5fd4) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Require GermConvenience 0.3.0, and adopt its response helpers

  The dependency floor moves to 0.3.0, which makes `BundledHTTPRequest.request`
  `private(set)` and `body` `let`. The three sites that assigned header fields in
  place now use `settingHeader(_:for:)`. Anything depending on oauth4swift resolves
  0.3.0 too.

  Drops the local `HTTPDataResponse.successOrThrow` copy in favour of the version
  lifted into GermConvenience as `expectSuccess(orError:)`, and collapses the
  hand-rolled `.result`/`.error` switches in the PAR and token-endpoint paths onto
  `get(mapError:)`.

  0.3.0 also fixes `HTTPDataResponse.success`, which both of those paths use: a 2xx
  whose body fails to decode now reports the real `DecodingError` rather than being
  retried as an error body — previously a malformed token response surfaced as
  `Errors.invalidRequest`. A non-2xx whose body is not an OAuth error response (a
  proxy's HTML, an empty body) now throws `HTTPResponseError.unsuccessful` with the
  status and bytes intact rather than a bare `DecodingError`.

### Patch Changes

- [#48](https://github.com/germ-network/oauth4swift/pull/48) [`4f12212`](https://github.com/germ-network/oauth4swift/commit/4f1221206cb9570130a84c2f56ed8309f7058129) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Make all AuthServerMetadata properties public

- [#53](https://github.com/germ-network/oauth4swift/pull/53) [`c0deef1`](https://github.com/germ-network/oauth4swift/commit/c0deef18ac2d2fdb46963083eb5b93ef4029e13a) Thanks [@nnabeyang](https://github.com/nnabeyang)! - Preserve refresh tokens when token refresh fails with transient OAuth server errors.

- [#56](https://github.com/germ-network/oauth4swift/pull/56) [`fc515f0`](https://github.com/germ-network/oauth4swift/commit/fc515f0b8ba5e2ef3b46c9f2db703c85ec488994) Thanks [@germ-mark](https://github.com/germ-mark)! - fix the client_secret_basic Authorization header: add the "Basic " scheme prefix and form-url-encode the client id and secret

- [#52](https://github.com/germ-network/oauth4swift/pull/52) [`0f47abc`](https://github.com/germ-network/oauth4swift/commit/0f47abc013d1796757a5be79ee1a01b70d915788) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Skip refresh token requests when the server does not advertise `refresh_token` in `grant_types_supported`

- [#48](https://github.com/germ-network/oauth4swift/pull/48) [`b165de4`](https://github.com/germ-network/oauth4swift/commit/b165de4fee2d5ab120cd67a0ed47e9b648530647) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Fix missing client_id when not using PAR for authorization

- [#57](https://github.com/germ-network/oauth4swift/pull/57) [`c0c2c42`](https://github.com/germ-network/oauth4swift/commit/c0c2c420513126e0e089a8688bc310e2a30950a4) Thanks [@germ-mark](https://github.com/germ-mark)! - Preserve the session on any refresh failure other than a 400 `invalid_grant`, including error bodies that aren't structured OAuth errors. A `TokenRefreshOptions.validate` that throws now propagates rather than terminating the session, per its documented contract that throwing means validity couldn't be resolved; a thrown `tokenInvalid` still terminates, since validators shared with the authorize flow signal invalidity that way.

- [#58](https://github.com/germ-network/oauth4swift/pull/58) [`8b826f4`](https://github.com/germ-network/oauth4swift/commit/8b826f45f9a509530a84fb486daa934796065813) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `OAuth.Errors.refreshNotSupported`

  Thrown by the refresh gate when the server's `grant_types_supported` excludes
  `refresh_token`, so the session is preserved (skip) rather than terminated, and
  callers can distinguish "this server can never refresh - plan around
  access-token expiry" from a transient failure. Note: adding a case to a public
  enum breaks exhaustive switches over `OAuth.Errors`; no known consumer has one.

- [#48](https://github.com/germ-network/oauth4swift/pull/48) [`1da4bb8`](https://github.com/germ-network/oauth4swift/commit/1da4bb891ae97967da6a7bf8fc3b333b81e647ab) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Add resolveMaybe to AuthServerMetadata to fetch optional URLs in AS metadata

- [#48](https://github.com/germ-network/oauth4swift/pull/48) [`88c1a79`](https://github.com/germ-network/oauth4swift/commit/88c1a796c8ebcee26f1ad57bf5047818448cb9f1) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Add notSupported error to OAuth.Errors

## 0.5.0

### Minor Changes

- [#43](https://github.com/germ-network/oauth4swift/pull/43) [`6646f16`](https://github.com/germ-network/oauth4swift/commit/6646f1638454241c95e8c41af6f7784f1c2996fb) Thanks [@germ-mark](https://github.com/germ-mark)! - \* pass the tokenRequest as a sendable protocol rather than a closure
  - separate out TokenRequestOptions into TokenRefreshOptions and TokenAuthorizeOptions
    - Implement those as protocols, so that TokenAuthorizeOptions can return an associated type
  - remove additional parameters from the Session state storage, defer to the client to process what it needs out of the additional parameters, return it in the validation output, and store it alongside this session archive

## 0.4.0

### Minor Changes

- [#45](https://github.com/germ-network/oauth4swift/pull/45) [`9810721`](https://github.com/germ-network/oauth4swift/commit/981072154d7ccf5310cd3d153ad8be2c127baa32) Thanks [@germ-mark](https://github.com/germ-mark)! - \* adjust sessioncapabilities to push state management to the implementer
  - adjust the refresh api to debounce for recently refreshed token

### Patch Changes

- [#42](https://github.com/germ-network/oauth4swift/pull/42) [`318c672`](https://github.com/germ-network/oauth4swift/commit/318c6729cfe4bd32689010e2cc6dbe2213c773cf) Thanks [@germ-mark](https://github.com/germ-mark)! - \* add a optional created date on Token, make the codesharing protocol internal
  - adjust the mocks to be more configurable
  - use TimeInterval consistently instead of Int

## 0.3.5

### Patch Changes

- [#40](https://github.com/germ-network/oauth4swift/pull/40) [`354d3e2`](https://github.com/germ-network/oauth4swift/commit/354d3e2c480b18c1a61881029a340f02f939a424) Thanks [@germ-mark](https://github.com/germ-mark)! - correctly use base64url encoding in dpop

## 0.3.4

### Patch Changes

- [#38](https://github.com/germ-network/oauth4swift/pull/38) [`dbffccf`](https://github.com/germ-network/oauth4swift/commit/dbffccfa1fb1d0f02f6b0781bb9fb32ad3e76674) Thanks [@germ-mark](https://github.com/germ-mark)! - adopt 0.2.1 germconvenience without base64urlencoded and with revised bundled http request

## 0.3.3

### Patch Changes

- [#34](https://github.com/germ-network/oauth4swift/pull/34) [`cbe874a`](https://github.com/germ-network/oauth4swift/commit/cbe874a199f3a988e82316b06fcfcfefe52ac8d2) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm)! - Move LazyResource to GermConvenience

## 0.3.2

### Patch Changes

- [#35](https://github.com/germ-network/oauth4swift/pull/35) [`6b47973`](https://github.com/germ-network/oauth4swift/commit/6b479730f871d02b98e04317cb6dd964d7e35e8e) Thanks [@germ-mark](https://github.com/germ-mark)! - expose api to refresh only, catch a bad response and reset the session by saving nil, and add a session archive merge operation

- [#35](https://github.com/germ-network/oauth4swift/pull/35) [`6b47973`](https://github.com/germ-network/oauth4swift/commit/6b479730f871d02b98e04317cb6dd964d7e35e8e) Thanks [@germ-mark](https://github.com/germ-mark)! - Patch authenticatedRequest to retry on a nonce failure

## 0.3.1

### Patch Changes

- [#31](https://github.com/germ-network/oauth4swift/pull/31) [`fe25ea0`](https://github.com/germ-network/oauth4swift/commit/fe25ea03e3fcecfc03491be97aa05a35c25ebaed) Thanks [@germ-mark](https://github.com/germ-mark)! - fix inverted nonce check branch on auth or resource server

## 0.3.0

### Minor Changes

- [#27](https://github.com/germ-network/oauth4swift/pull/27) [`3e6a1e8`](https://github.com/germ-network/oauth4swift/commit/3e6a1e8b5e294683c4b4492b3224ea72e7cff3de) Thanks [@germ-mark](https://github.com/germ-mark)! - Discovery endpoints should return an optional

- [#30](https://github.com/germ-network/oauth4swift/pull/30) [`546a5ef`](https://github.com/germ-network/oauth4swift/commit/546a5ef4aa1cfa1af6e9a11e549e5f31aaef4728) Thanks [@ThisIsMissEm](https://github.com/ThisIsMissEm), [@germ-mark](https://github.com/germ-mark)! -

  ## The package product is now named `OAuth4Swift`

  This frees up `OAuth` to be a type namespace (we don't want a Type and Module with the same name, see: https://forums.swift.org/t/fixing-modules-that-contain-a-type-with-the-same-name/3025)

  ## Collecting types under `OAuth` namespace

  This isn't a comprehensive renaming, but types that were worked on in this PR mostly got collected under `OAuth`

  - This formalizes a number of types previously prefixed OAuth
  - Mainly, OAuth provides a home for free functions previously under `OAuthComponents`, that comprise a main contribution of this repository
  - Allows for a little bit of concision when operating within `OAuth` when we can drop the prefix. (i.e. we should make a namespace anytime we're tempted to start a prefix pattern)

  ## Client Auth

  Oh yea, we wanted to implement client authentication. The client auth types give us a correct home for "free" functions that were previously hung on auth configs. `ClientAuth` provides us a useful namespace for separating ClientAuth from other portions

  Client Auth is separated into two protocols for the Client Auth components and composition

  ### `ClientAuth.Component`

  - Implementations of objects that perform the authetication conform to this protocol. They're expected to be held within a client/session, so don't themselves hold on to e.g. clientId and instead take it as a parameter when authenticating.
  - Some auth components may contain mutable state. These can be implemented as classes, contained in a parent actor protecting all session state, and the access pattern supports this

  ### `ClientAuth.Authenticable`

  - Every client must use authentication, so `SessionCapabilities` now conforms to `ClientAuthenticable`
  - The other type of object conforming to `ClientAuthenticable` is the initial authorize flow, which needs to perform negotiation between the auth methods the client and server support. `Authorizer.negotiate` performs this, returning a stub ClientAuthenticable from which the initial state can be saved and re-restored into a Session object.

  ## Archive/Restore

  We now have 2 portions of mutable state in the session archive: tokenState, and clientAuth. The session archive immutably saves the auth type, and exposes methods to merge in updated clientAuth and tokenState archives.

### Patch Changes

- [#18](https://github.com/germ-network/oauth4swift/pull/18) [`97134e2`](https://github.com/germ-network/oauth4swift/commit/97134e2d82b8d5fb545197d64a84ba33b022214c) Thanks [@anna-germ](https://github.com/anna-germ)! - Make AuthServerMetadata's dpopSigningAlgValuesSupported list public

- [#23](https://github.com/germ-network/oauth4swift/pull/23) [`d750a1b`](https://github.com/germ-network/oauth4swift/commit/d750a1b62c6748eab8dc829d00bf19be3613dbc8) Thanks [@germ-mark](https://github.com/germ-mark)! - fix: apply refreshed session state after token rotation

- [#19](https://github.com/germ-network/oauth4swift/pull/19) [`31d45aa`](https://github.com/germ-network/oauth4swift/commit/31d45aacc9dd1dfa345838ed9fc393b1eb5ecfe6) Thanks [@germ-mark](https://github.com/germ-mark)! - Remove duplicate lazy Issuer requirement, which can be fulfilled by lazyAuthServerMetadata

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
