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

- **The text bridge lives in `swift-secret-bytes` now** — `SecretBytes(utf8:)`
  and `SecretBytes.utf8String()`, added in 0.6.0 (germ-network/swift-secret-bytes#16),
  rather than a local helper. A `String` is materialized only where one is
  actually needed — the `Authorization` header and the RFC 7009 revocation form
  body — as a transient copy. This package revision-pins that addition until
  0.6.0 cuts.
- **`OAuth.TokenGrammar`** validates a token on ingest against RFC 6749's own
  grammar — Appendix A.12/A.17 `access-token`/`refresh-token = 1*VSCHAR`, with
  `VSCHAR = %x20-7E` (Appendix A) — and throws `OAuth.Errors.malformedToken` on
  a value outside it. RFC 6750 §2.1's narrower `b64token` is deliberately **not**
  enforced at ingest: it constrains a Bearer *credential*, not the token, and
  §§1.4/1.5 make the value opaque to the client. `OAuth.TokenGrammar.isBearerSafe(_:)`
  exposes it for callers that need it.
- **`OAuth.Token.asBearerToken`** is the canonical bearer-form materialization,
  on the shared `Token` protocol so access and refresh tokens both get it.
- The `Authorization` header path materializes the token once, outside the
  DPoP/Bearer branch, instead of in each arm.
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
