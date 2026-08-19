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
			testDescription:
				"percent-encoded path segment is preserved in the request URL",
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
			testDescription:
				"default port is preserved in the request URL, stripped from the canonical identifier",
			source: "https://api.example.com:443/xrpc",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL:
				"https://api.example.com:443/.well-known/oauth-protected-resource/xrpc",
			expectedCanonicalIdentifier: "https://api.example.com/xrpc"
		),
		.init(
			testDescription:
				"host case is preserved in the request URL, lowercased in the canonical identifier",
			source: "https://API.Example.COM/xrpc",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL:
				"https://API.Example.COM/.well-known/oauth-protected-resource/xrpc",
			expectedCanonicalIdentifier: "https://api.example.com/xrpc"
		),
		.init(
			testDescription:
				"percent-encoding hex case is preserved in the request URL, normalized to uppercase in the canonical identifier",
			source: "https://api.example.com/user%2fname",
			segment: OAuth.wellKnownProtectedResource,
			expectedURL:
				"https://api.example.com/.well-known/oauth-protected-resource/user%2fname",
			expectedCanonicalIdentifier: "https://api.example.com/user%2Fname"
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

	@Test(
		"Two Unicode-canonically-equivalent identifiers produce the same canonical identifier"
	)
	func unicodeNormalizationEquivalence() throws {
		let precomposed = try #require(URL(string: "https://api.example.com/caf\u{00E9}"))
		let decomposed = try #require(URL(string: "https://api.example.com/cafe\u{0301}"))
		let a = try precomposed.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		let b = try decomposed.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(a.canonicalIdentifier == b.canonicalIdentifier)
	}

	@Test("The legacy URL coincides with the primary URL for a path-less identifier")
	func legacyURLCoincidesWhenPathless() throws {
		let source = try #require(URL(string: "https://api.example.com"))
		let discovery = try source.insertingWellKnownSegment(
			OAuth.wellKnownProtectedResource)
		#expect(discovery.legacyURL == discovery.url)
	}

	@Test("The legacy URL appends the segment after the path")
	func legacyURLAppendsAfterPath() throws {
		let source = try #require(URL(string: "https://api.example.com/xrpc"))
		let discovery = try source.insertingWellKnownSegment(
			OAuth.wellKnownProtectedResource)
		#expect(
			discovery.legacyURL.absoluteString
				== "https://api.example.com/xrpc/.well-known/oauth-protected-resource"
		)
	}

	enum ExpectedRejection: Sendable {
		case missingScheme
		case missingHost
		case invalidResourceIdentifier

		func matches(_ error: OAuth.Errors) -> Bool {
			switch (self, error) {
			case (.missingScheme, .missingScheme),
				(.missingHost, .missingHost),
				(.invalidResourceIdentifier, .invalidResourceIdentifier):
				true
			default:
				false
			}
		}
	}

	struct InvalidCase: Sendable, CustomTestStringConvertible {
		let testDescription: String
		let source: String
		let expected: ExpectedRejection
	}

	static let invalidCases: [InvalidCase] = [
		.init(
			testDescription: "missing host", source: "https:///path",
			expected: .missingHost),
		.init(
			testDescription: "missing scheme, host present",
			source: "//api.example.com/xrpc",
			expected: .missingScheme
		),
		.init(
			testDescription: "multiple trailing slashes leave an empty path segment",
			source: "https://api.example.com/xrpc///",
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "a \".\" path segment",
			source: "https://api.example.com/./xrpc",
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "a \"..\" path segment",
			source: "https://api.example.com/../xrpc",
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "a percent-encoded \".\" path segment",
			source: "https://api.example.com/%2e/xrpc",
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "a percent-encoded \"..\" path segment",
			source: "https://api.example.com/%2e%2e/xrpc",
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "an empty path segment mid-path",
			source: "https://api.example.com/a//b",
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "a query string",
			source: "https://api.example.com/xrpc?tenant=foo",
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "a fragment",
			source: "https://api.example.com/xrpc#frag",
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "userinfo",
			source: "https://user:pw@api.example.com/xrpc",
			expected: .invalidResourceIdentifier
		),
	]

	@Test("Rejects malformed identifiers with the specific error", arguments: invalidCases)
	func rejectsInvalidIdentifiers(_ testCase: InvalidCase) throws {
		let source = try #require(URL(string: testCase.source))
		do {
			_ = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
			Issue.record("expected \(testCase.expected) to be thrown")
		} catch let error as OAuth.Errors {
			#expect(testCase.expected.matches(error), "got \(error)")
		}
	}
}
