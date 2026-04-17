Building blocks for an OAuth 2.1 client.

(This is pre-release and not yet stable. It is initially built for the atproto OAuth requirements (DPoP, PAR))

See [AtprotoOAuth](https://github.com/germ-network/AtprotoOAuth) for an example of using these
to build a full featured client.

You can use just call the static methods of `OAuthComponents`.

You can also provide an implementation of `OAuthSessionCapabilities` that holds token state, and use
the provided default implementation of an authorized request that automatically refreshes the token
if necessary


## Contributing and Collaboration
We welcome contributions!

Please follow our [guidelines for contributing code](./CONTRIBUTING.md)

To give clarity of what is expected of our members, Germ has adopted the
code of conduct defined by the Contributor Covenant. This document is used
across many open source communities, and we think it articulates our values
well. For more, see the [Code of Conduct](./CODE_OF_CONDUCT.md)