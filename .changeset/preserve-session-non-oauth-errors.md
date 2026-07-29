---
"@germ-network/oauth4swift": patch
---

Preserve the session on any refresh failure other than a 400 `invalid_grant`, including error bodies that aren't structured OAuth errors. A `TokenRefreshOptions.validate` that throws now propagates rather than terminating the session, per its documented contract that throwing means validity couldn't be resolved; a thrown `tokenInvalid` still terminates, since validators shared with the authorize flow signal invalidity that way.
