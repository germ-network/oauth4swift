---
"@germ-network/oauth4swift": patch
---

Preserve the existing refresh token when a refresh response omits `refresh_token`.

RFC 6749 §6 lets an authorization server renew the access token without rotating
the refresh token, in which case the client keeps using the one it already holds.
The refresh path rebuilt the token state from the response alone, so an omitted
`refresh_token` cleared the stored one. The session was then left with nothing to
send on the next refresh and effectively signed the user out once the access token
expired.

The refresh path now carries the existing refresh token over. `fetchedOn` is
restamped so the `refresh(debounce:)` gate still sees that a refresh just happened,
and a `refresh_token_timeout` that arrives without a `refresh_token` now restates
the preserved token's expiry, per
[draft-ietf-oauth-refresh-token-expiration](https://www.ietf.org/archive/id/draft-ietf-oauth-refresh-token-expiration-01.html):
"The authorization server MAY return these values even if the response contains no
refresh_token field in the response, in which case the values correspond to the
presented refresh_token." A response that does include a `refresh_token` continues
to replace the stored one.
