---
"@germ-network/oauth4swift": patch
---

Add support for draft-ietf-oauth-refresh-token-expiration

The new [draft-ietf-oauth-refresh-token-expiration](https://drafts.oauth.net/rt-expiration/draft-ietf-oauth-refresh-token-expiration.html) from the OAuth WG at IETF allows for Authorization Servers to signal to clients when:
- the Authorization Grant expires
- the Refresh Token expires

This allows a client to know that the refresh token isn't even valid anymore, before attempting to do a token refresh.
