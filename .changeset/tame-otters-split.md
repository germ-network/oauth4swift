---
"@germ-network/oauth4swift": patch
---

Fix build against GermConvenience 0.8.0, which split `HTTPDataResponse`,
`HTTPFetcher`, `BundledHTTPRequest`, `HTTPStreamFetcher`, and `URLScheme` out of
the base `GermConvenience` library into a new `GermConvenienceHTTP` product.
Adds the `GermConvenienceHTTP` product dependency and the matching import
everywhere those types are used, and raises the floor to `from: "0.8.0"` since
that's the first version carrying the split product this package now needs.

No public API change — this only restores buildability against current
GermConvenience releases.
