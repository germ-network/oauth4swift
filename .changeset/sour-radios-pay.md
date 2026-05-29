---
"@germ-network/oauth4swift": minor
---

* pass the tokenRequest as a sendable protocol rather than a closure
* separate out TokenRequestOptions into TokenRefreshOptions and TokenAuthorizeOptions
    * Implement those as protocols, so that TokenAuthorizeOptions can return an associated type
* remove additional parameters from the Session state storage, defer to the client to process what it needs out of the additional parameters, return it in the validation output, and store it alongside this session archive
