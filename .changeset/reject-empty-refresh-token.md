---
"@germ-network/oauth4swift": patch
---

Treat a present-but-empty `refresh_token` in a token response as absent. Some
servers send `"refresh_token": ""` rather than omitting the field; the value
passed the nil-only guard and overwrote the stored token with an empty value,
undoing the preservation added for omitted refresh tokens. An empty value now
falls through to the existing token, which is kept in force.
