---
"@germ-network/oauth4swift": minor
---

Require GermConvenience 0.3.0, and adopt its response helpers

The dependency floor moves to 0.3.0, which makes `BundledHTTPRequest.request`
`private(set)` and `body` `let`. The three sites that assigned header fields in
place now use `settingHeader(_:for:)`. Anything depending on oauth4swift resolves
0.3.0 too.

Drops the local `HTTPDataResponse.successOrThrow` copy in favour of the version
lifted into GermConvenience as `expectSuccess(orError:)`, and collapses the
hand-rolled `.result`/`.error` switches in the PAR and token-endpoint paths onto
`get(mapError:)`.

0.3.0 also fixes `HTTPDataResponse.success`, which both of those paths use: a 2xx
whose body fails to decode now reports the real `DecodingError` rather than being
retried as an error body — previously a malformed token response surfaced as
`Errors.invalidRequest`. A non-2xx whose body is not an OAuth error response (a
proxy's HTML, an empty body) now throws `HTTPResponseError.unsuccessful` with the
status and bytes intact rather than a bare `DecodingError`.
