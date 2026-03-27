---
"@germ-network/oauth4swift": minor
---

Change signature for tokenValidator

`tokenValidator` previously returned a `SessionState.Mutable` which leaked internal implementation details into the consuming code. Instead, `tokenValidator` now just asynchronously returns a `Bool` and the `SessionState.Mutable` is constructed in the `processAuthorizationCodeOAuth2Response` method and the private `refresh` method in `OAuthSessionCapabilities`.

The `tokenValidator` also now receives an "immutable" copy of the previous `SessionState`, allowing clients to validate that for instance the `additionalParams` on a token haven't changed during refresh. When `tokenValidator` is called from `processAuthorizationCodeOAuth2Response`, the previous `SessionState` is nil, since we don't have a previous session.
