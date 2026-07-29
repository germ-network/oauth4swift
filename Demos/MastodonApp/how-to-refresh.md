# Adding Token Refresh Support

Mastodon access tokens don't expire, so `MastodonAgent.startRefresh` currently returns `nil`
and `MastodonTokenRefreshOptions.validate` is a no-op gate. If tokens did expire, here is what
would need to change.

## 1. Gate refresh on server metadata and a stored refresh token

`OAuth.SessionCapabilities` already checks `grant_types_supported` before calling the refresh
closure (`OAuthSession+AuthRequest.swift`). No server-side metadata change is needed — if the
Mastodon instance advertises `"refresh_token"` in `grant_types_supported` and the initial token
response includes a refresh token, the library will attempt refresh automatically.

## 2. Validate the refresh response (`MastodonTokenRefreshOptions`)

`TokenRefreshOptions.validate` receives the refresh token response and must return `Bool`:
`true` to accept the new token state, `false` to terminate the session.

```swift
func validate(
    tokenResponse: TokenEndpointResponse,
    authServerMetadata: AuthServerMetadata,
    previousState: OAuth.SessionState.Snapshot
) async throws -> Bool {
    tokenResponse.refreshToken != nil
        || previousState.grantScopes?.contains("offline_access") == true
}
```

- `tokenResponse.refreshToken != nil` — server returned a new refresh token, so the session
  is ongoing.
- `previousState.grantScopes?.contains("offline_access")` — the original grant explicitly
  authorized long-lived offline access. Prefer `grantScopes` over the refresh response's
  `scope` field, which may be omitted when unchanged.

The `offline_access` scope here comes from the OIDC vocabulary, and is what I proposed for an increment, client-controlled upgrade to Mastodon's OAuth implementation to enable refresh tokens for some apps but not others: https://github.com/mastodon/mastodon/pull/27948/

## 3. Add a state machine and save stream to `MastodonAgent`

See `AtprotoOAuthAgent` for the reference implementation. The key pieces:

- Replace `let tokenState` with `var state: State` — an enum of `.active(OAuth.SessionState)`,
  `.refreshing(Task<AccessToken, Error>, previous: OAuth.SessionState)`, and `.expired`.
- Add `AsyncStream<OAuth.SessionState.TokenState?>` (`saveStream`) with a `Continuation`.
- Implement `startRefresh` to coalesce concurrent refresh calls (return the in-flight task from
  `.refreshing`), call the refresh closure, yield the result to `saveContinuation`, and
  transition state accordingly.
- `MastodonClient.restore()` returns `(MastodonAgent, AsyncStream<TokenState?>)`.

## 4. Persist updated archives in `AppState`

After calling `restore()`, observe the save stream:

```swift
let (agent, saveStream) = try await client.restore(archive: archive)
Task { [weak self] in
    for await tokenState in saveStream {
        guard let self else { return }
        if tokenState != nil, let updated = try? await agent.archive {
            self.save(archive: updated)
        } else {
            self.clearSaved()
            await MainActor.run { self.session = nil }
        }
    }
}
```

A `nil` yield means the session expired (refresh failed) — clear Keychain and log the user out.
