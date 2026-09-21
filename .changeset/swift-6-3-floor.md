---
"@germ-network/oauth4swift": minor
---

Raise the minimum Swift toolchain to 6.3.

`swift-tools-version` was 6.2 while CI only ever tested `swift:latest`, so the declared
floor was never actually exercised. Linux CI now tests the floor, the current release,
and `latest` as an early warning for the next one.
