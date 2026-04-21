---
"@germ-network/oauth4swift": minor
---

## The package product is now named `OAuth4Swift`
This frees up `OAuth` to be a type namespace (we don't want a Type and Module with the same name, see: https://forums.swift.org/t/fixing-modules-that-contain-a-type-with-the-same-name/3025)

## Collecting types under `OAuth` namespace
This isn't a comprehensive renaming, but types that were worked on in this PR mostly got collected under `OAuth`
- This formalizes a number of types previously prefixed OAuth
- Mainly, OAuth provides a home for free functions previously under `OAuthComponents`, that comprise a main contribution of this repository
- Allows for a little bit of concision when operating within `OAuth` when we can drop the prefix. (i.e. we should make a namespace anytime we're tempted to start a prefix pattern)

## Client Auth
Oh yea, we wanted to implement client authentication. The client auth types give us a correct home for "free" functions that were previously hung on auth configs. `ClientAuth` provides us a useful namespace for separating ClientAuth from other portions 

Client Auth is separated into two protocols for the Client Auth components and composition

### `ClientAuth.Component`
* Implementations of objects that perform the authetication conform to this protocol. They're expected to be held within a client/session, so don't themselves hold on to e.g. clientId and instead take it as a parameter when authenticating. 
* Some auth components may contain mutable state. These can be implemented as classes, contained in a parent actor protecting all session state, and the access pattern supports this

### `ClientAuth.Authenticable`
* Every client must use authentication, so `SessionCapabilities` now conforms to `ClientAuthenticable`
* The other type of object conforming to `ClientAuthenticable` is the initial authorize flow, which needs to perform negotiation between the auth methods the client and server support. `Authorizer.negotiate` performs this, returning a stub ClientAuthenticable from which the initial state can be saved and re-restored into a Session object.

## Archive/Restore
We now have 2 portions of mutable state in the session archive: tokenState, and clientAuth. The session archive immutably saves the auth type, and exposes methods to merge in updated clientAuth and tokenState archives.
