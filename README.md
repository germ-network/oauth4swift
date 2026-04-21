Building blocks for an OAuth 2.1 client.

(This is pre-release and not yet stable. It is initially built for the atproto OAuth requirements (DPoP, PAR))

See [AtprotoOAuth](https://github.com/germ-network/AtprotoOAuth) for an example of using these
to build a full featured client.

This package comprises components and compositions of those components with
some adopter-supplied objects that handle application-specific state.

# Components
This package supplies:
- free functions under the `OAuth` namespace for making requests of OAuth endpoints.
- object implementations of client authentication methods
- object implementations of DPoP request signing

# Compositions
To construct a full authentication flow, an adopter can
1. Supply an implementation of the `Authorizer` protocol
2. OAuth4Swift provides an implementation of `performUserAuthentication`,
relying on the implementation of `Authorizer` to negotiate initial client
authentication and produce a stub `OAuth.ClientAuth.Authenticable` for the intitial
authorization flow. `performUserAuthentication` produces a session archive.
3. The adopter can supply an implementation of `SessionCapabilities` that
restores from a `OAuth.SessionState.Archive`. OAuth4Swift provides default implementations
of protected resource requests and token refresh methods.

## Contributing and Collaboration
We welcome contributions!

Please follow our [guidelines for contributing code](./CONTRIBUTING.md)

To give clarity of what is expected of our members, Germ has adopted the
code of conduct defined by the Contributor Covenant. This document is used
across many open source communities, and we think it articulates our values
well. For more, see the [Code of Conduct](./CODE_OF_CONDUCT.md)

