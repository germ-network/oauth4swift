---
"@germ-network/oauth4swift": minor
---

Hold the session's secrets in zeroizing custody via `swift-secret-bytes`.

`OAuth.DPoP.Key.keyData` is now a `SecretBytes` (was `Data`), and
`OAuth.AccessToken.value` / `OAuth.RefreshToken.value` are `SecretBytes` (were
`String`). The persisted `OAuth.SessionState.Archive` therefore carries
`@SecretField` secrets and is `Codable` **only** into a `SecretArchive`; any
other coder (e.g. `JSONEncoder`) throws rather than writing a private scalar or
token plainly. `AccessToken`/`RefreshToken`/`DPoP.Key` drop `Hashable` — a
secret's hash is a leak vector, and `SecretField` is deliberately not `Hashable`
— keeping `Equatable`.

- **`OAuth.SecretText`** is the one, documented bridge between a secret's bytes
  and its UTF-8 text form (RFC 6749 tokens are ASCII, so it is lossless in both
  directions). A `String` is materialized only where one is actually needed —
  the `Authorization` header (`OAuth.Token.materializedValue`) and the RFC 7009
  revocation form body (`OAuth.RevocableToken.materializedValue()`) — as a
  transient copy. The token values no longer round-trip through `.utf8` at each
  call site.
- **Legacy plaintext archives still decode.** `OAuth.SessionState.LegacyArchive`
  is the pre-zeroizing JSON shape (token `String`s, base64 `Data` DPoP scalar),
  and `OAuth.SessionState.Archive.decodeLegacy(_:)` migrates one into the
  zeroizing form — so an app whose own archive nests the session archive can
  keep reading what it already persisted.

**Breaking:** the `String`-based token initializers are now `throws` (an empty
token cannot be a `SecretBytes`), the token/key types drop `Hashable`, and the
platform floor rises to iOS 18 (swift-secret-bytes 0.5.0's own floor). The
`OAuth.SessionState.*.mock()` helpers are now `throws` accordingly.
`OAuth.DPoP.Key.generateP256()` stays non-`throws`: the wrap can only fail on an
empty scalar, which a generated P-256 key never is.
