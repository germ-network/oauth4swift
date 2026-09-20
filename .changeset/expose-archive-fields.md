---
"@germ-network/oauth4swift": minor
---

Expose `OAuth.SessionState.Archive`'s `clientId`, `dPopKey`, and `issuingServer`, and `OAuth.DPoP.Key`'s `alg` and `keyData`, as public; add public inits to `AccessToken`, `RefreshToken`, and `TokenState` and expose `TokenState.grantExpiry` / `.scopes`.

A consumer re-homing a session archive (and its secrets) into zeroizing custody needs to read and rebuild these without the type's synthesized `Codable` shape — a bridge through a coder keyed on property names breaks silently, at runtime, on any field rename or hand-written `CodingKeys`. Widening visibility and construction removes that fragility. Behavior is unchanged.

Also widens the `swift-crypto` dependency to `from: "5.0.0"` (org-wide move to swift-crypto 5; no code changes needed, full suite passes).
