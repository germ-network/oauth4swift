Building blocks for an OAuth 2.1 client.

(This is pre-release and not yet stable. It is initially built for the atproto OAuth requirements (DPoP, PAR))

See [AtprotoOAuth](https://github.com/germ-network/AtprotoOAuth) for an example of using these
to build a full featured client.

You can use just call the static methods of `OAuthComponents`.

You can also provide an implementation of `OAuthSessionCapabilities` that holds token state, and use
the provided default implementation of an authorized request that automatically refreshes the token
if necessary



### Linting and Practices
The repo has a .editorconfig and .swift-format setup. We use both swift
formatter and linter:
```
swift format . -ri && swift format lint . -r
```

We also use the [periphery static analyzer](https://github.com/peripheryapp/periphery) and have a configured `periphery.yml`