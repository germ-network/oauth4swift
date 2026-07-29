---
"@germ-network/oauth4swift": patch
---

Preserve the session on any refresh failure other than a 400 `invalid_grant`, including error bodies that aren't structured OAuth errors.
