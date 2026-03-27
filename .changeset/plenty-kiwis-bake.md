---
"@germ-network/oauth4swift": patch
---

Improve error handling in `validateAuthResponse`

When we receive an `error` parameter back from the `userAuthenticator` (e.g., the user denies the authorization request), `validateAuthResponse` will now throw more specific errors than just `OAuthError.redirectError`. The following more specific errors are supported:
- `OAuthError.accessDenied` for when the user denies the authorization grant
- `OAuthError.invalidRequest` if the authorization request was malformed
- `OAuthError.invalidScope` if the scope requested was invalid

Whilst there are [more expected OAuth Errors](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1), the other errors are throw as `OAuthError.redirectError(error, errorDescription?)`. The `error` parameter to the `OAuthError.redirectError` is always forced to lowercase, per specification.

We don't currently support `error_uri`, only `error` and `error_description`.
