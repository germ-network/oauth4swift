---
"@germ-network/oauth4swift": patch
---

Build the DPoP proof's `htu` claim from GermConvenience's `URL.origin` plus the
percent-encoded path (RFC 9449 §4.2). Previously a percent-encoded path was
decoded (`/a%2Fb` became `/a/b`), so `htu` didn't match the URL actually
requested, and the scheme kept its original case. The local `URL.origin`
helper is removed in favour of GermConvenience's.
