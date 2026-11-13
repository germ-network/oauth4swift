---
"@germ-network/oauth4swift": patch
---

Encode DPoP JWT header and claims as unpadded base64url (RFC 7515), so strict authorization servers such as blacksky.app no longer reject the proof with "Invalid padding".
