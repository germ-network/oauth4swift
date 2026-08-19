import Foundation
import Testing

@testable import OAuth4Swift

@Suite("well-known metadata URL construction")
struct WellKnownMetadataURLTests {
	struct BuildCase: Sendable, CustomTestStringConvertible {
		let testDescription: String
		let source: String
		let segment: String
		let expectedURL: String
		let expectedCanonicalIdentifier: String
	}

	static let buildCases: [BuildCase] = [
		.init(
			testDescription: "no path",
			source: "https://api.example.com",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL: "https://api.example.com/.well-known/oauth-protected-resource",
			expectedCanonicalIdentifier: "https://api.example.com"
		),
		.init(
			testDescription: "root-only path normalizes to the no-path form",
			source: "https://api.example.com/",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL: "https://api.example.com/.well-known/oauth-protected-resource",
			expectedCanonicalIdentifier: "https://api.example.com"
		),
		.init(
			testDescription: "trailing slash is stripped (RFC 8414 §3.1)",
			source: "https://api.example.com/xrpc/",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL:
				"https://api.example.com/.well-known/oauth-protected-resource/xrpc",
			expectedCanonicalIdentifier: "https://api.example.com/xrpc"
		),
		.init(
			testDescription: "single path segment",
			source: "https://api.example.com/xrpc",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL:
				"https://api.example.com/.well-known/oauth-protected-resource/xrpc",
			expectedCanonicalIdentifier: "https://api.example.com/xrpc"
		),
		.init(
			testDescription: "multi-segment path",
			source: "https://api.example.com/a/b/c",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL:
				"https://api.example.com/.well-known/oauth-protected-resource/a/b/c",
			expectedCanonicalIdentifier: "https://api.example.com/a/b/c"
		),
		.init(
			testDescription: "percent-encoded path segment is preserved",
			source: "https://api.example.com/user%20name",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL:
				"https://api.example.com/.well-known/oauth-protected-resource/user%20name",
			expectedCanonicalIdentifier: "https://api.example.com/user%20name"
		),
		.init(
			testDescription: "non-default port is preserved",
			source: "https://api.example.com:8443/xrpc",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL:
				"https://api.example.com:8443/.well-known/oauth-protected-resource/xrpc",
			expectedCanonicalIdentifier: "https://api.example.com:8443/xrpc"
		),
		.init(
			testDescription: "authorization server issuer with a path",
			source: "https://issuer.example.com/tenant1",
			segment: OAuth.wellKnownAuthorizationServer,
			expectedURL:
				"https://issuer.example.com/.well-known/oauth-authorization-server/tenant1",
			expectedCanonicalIdentifier: "https://issuer.example.com/tenant1"
		),
		.init(
			testDescription: "authorization server issuer without a path",
			source: "https://issuer.example.com",
			segment: OAuth.wellKnownAuthorizationServer,
			expectedURL:
				"https://issuer.example.com/.well-known/oauth-authorization-server",
			expectedCanonicalIdentifier: "https://issuer.example.com"
		),
	]

	@Test("Builds the well-known URL and canonical identifier", arguments: buildCases)
	func buildsDiscoveryRequest(_ testCase: BuildCase) throws {
		let source = try #require(URL(string: testCase.source))
		let discovery = try source.insertingWellKnownSegment(testCase.segment)
		#expect(discovery.url.absoluteString == testCase.expectedURL)
		#expect(discovery.canonicalIdentifier == testCase.expectedCanonicalIdentifier)
	}

	struct InvalidCase: Sendable, CustomTestStringConvertible {
		let testDescription: String
		let source: String
	}

	static let invalidCases: [InvalidCase] = [
		.init(testDescription: "missing host", source: "https:///path"),
		.init(
			testDescription: "multiple trailing slashes leave an empty path segment",
			source: "https://api.example.com/xrpc///"
		),
		.init(
			testDescription: "a \".\" path segment",
			source: "https://api.example.com/./xrpc"),
		.init(
			testDescription: "a \"..\" path segment",
			source: "https://api.example.com/../xrpc"
		),
		.init(
			testDescription: "an empty path segment mid-path",
			source: "https://api.example.com/a//b"
		),
		.init(
			testDescription: "a query string",
			source: "https://api.example.com/xrpc?tenant=foo"
		),
		.init(testDescription: "a fragment", source: "https://api.example.com/xrpc#frag"),
		.init(
			testDescription: "userinfo",
			source: "https://user:pw@api.example.com/xrpc"
		),
	]

	@Test("Rejects malformed identifiers", arguments: invalidCases)
	func rejectsInvalidIdentifiers(_ testCase: InvalidCase) throws {
		let source = try #require(URL(string: testCase.source))
		#expect(throws: OAuth.Errors.self) {
			try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		}
	}
}
