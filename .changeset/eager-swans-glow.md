---
"@germ-network/oauth4swift": patch
---

Add Android CI. No source change — the package was already fully portable (it already
carries two `canImport(FoundationNetworking)` gates), so this just wires up the leg.

Verified with a clean Android cross-build including the test target
(`swift build --build-tests --swift-sdk aarch64-unknown-linux-android28`) — builds and
links green from an empty `.build`.
