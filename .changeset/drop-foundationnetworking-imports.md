---
"@germ-network/oauth4swift": patch
---

Drop unused `FoundationNetworking` imports so non-Apple platforms do not link it, and require GermConvenience 0.13.0, whose HTTP product no longer imports it. `URLSession` conforms to `HTTPFetcher` from the `GermConvenienceURLSession` product since that release, so callers passing a `URLSession` add that product.
