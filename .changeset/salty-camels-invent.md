---
"@germ-network/oauth4swift": minor
---

Rename parameters for consistency

The following parameters were renamed:
- `redirectURL` to `redirectURI`
- `callbackURL` is now `redirectURI` in `OAuthClient` (the replacement for `AppCredentials`)
- `func finishAuthorization` and `func validateAuthResponse` now take a `callbackURL` parameter instead of `redirectURI`
- `func validateAuthResponse` now can also take just the parameters from the `callbackURL` via `callbackParameters` instead, this is an array of `URLQueryItem`
- `func validateAuthResponse` now returns a branded type `AuthResponseParameters` instead of a `ParsedRedirect`. This is the `callbackParameters` passed to `authorizationCodeGrantRequest`, which has a subscript to get the values for an individual query parameter, e.g,  `callbackParameters["code"].first`
- `func authorizationCodeGrantRequest` now accepts a `redirectURI: URL` and `callbackParameters: AuthResponseParameters` parameters instead of `redirectUrl` and `parsedRedirect`
- `func validateAuthResponse` now takes a `callbackURL` parameter instead of `redirectURL` and `expectedState` is now an optional string, allowing for usage against OAuth 2.0 servers, where the `state` parameter is not required. (`AuthorizeInputs` still generates a `state` parameter value by default, and this isn't optional)
