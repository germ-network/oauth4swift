import Foundation
import Testing

@testable import OAuth4Swift

@Suite("Discovery identifier and well-known URLs")
struct DiscoveryIdentifierTests {
	struct BuildCase: Sendable, CustomTestStringConvertible {
		let testDescription: String
		let source: String
		let metadata: OAuth.DiscoveryIdentifier.Metadata
		let expectedURL: String
	}

	static let buildCases: [BuildCase] = [
		.init(
			testDescription: "no path",
			source: "https://rs.example.com",
			metadata: .protectedResource,
			expectedURL: "https://rs.example.com/.well-known/oauth-protected-resource"
		),
		.init(
			testDescription:
				"resource: the slash following the host is removed (RFC 9728 §3.1)",
			source: "https://rs.example.com/",
			metadata: .protectedResource,
			expectedURL: "https://rs.example.com/.well-known/oauth-protected-resource"
		),
		.init(
			testDescription:
				"resource: a terminating path slash is kept (RFC 9728 §3.1)",
			source: "https://rs.example.com/tenant1/",
			metadata: .protectedResource,
			expectedURL:
				"https://rs.example.com/.well-known/oauth-protected-resource/tenant1/"
		),
		.init(
			testDescription: "resource: a query follows the path (RFC 9728 §3.1)",
			source: "https://rs.example.com/tenant1?v=2",
			metadata: .protectedResource,
			expectedURL:
				"https://rs.example.com/.well-known/oauth-protected-resource/tenant1?v=2"
		),
		.init(
			testDescription: "resource: a query with only a root path",
			source: "https://rs.example.com/?v=2",
			metadata: .protectedResource,
			expectedURL:
				"https://rs.example.com/.well-known/oauth-protected-resource?v=2"
		),
		.init(
			testDescription: "resource: a query with no path",
			source: "https://rs.example.com?v=2",
			metadata: .protectedResource,
			expectedURL:
				"https://rs.example.com/.well-known/oauth-protected-resource?v=2"
		),
		.init(
			testDescription: "issuer: a terminating slash is removed (RFC 8414 §3.1)",
			source: "https://as.example.com/tenant1/",
			metadata: .authorizationServer(.oauth2),
			expectedURL:
				"https://as.example.com/.well-known/oauth-authorization-server/tenant1"
		),
		.init(
			testDescription: "single path segment",
			source: "https://rs.example.com/tenant1",
			metadata: .protectedResource,
			expectedURL:
				"https://rs.example.com/.well-known/oauth-protected-resource/tenant1"
		),
		.init(
			testDescription: "multi-segment path",
			source: "https://rs.example.com/a/b/c",
			metadata: .protectedResource,
			expectedURL:
				"https://rs.example.com/.well-known/oauth-protected-resource/a/b/c"
		),
		.init(
			testDescription: "percent-encoding is preserved as given",
			source: "https://rs.example.com/user%2fname",
			metadata: .protectedResource,
			expectedURL:
				"https://rs.example.com/.well-known/oauth-protected-resource/user%2fname"
		),
		.init(
			testDescription: "non-default port is preserved",
			source: "https://rs.example.com:8443/tenant1",
			metadata: .protectedResource,
			expectedURL:
				"https://rs.example.com:8443/.well-known/oauth-protected-resource/tenant1"
		),
		.init(
			testDescription: "default port is preserved as given",
			source: "https://rs.example.com:443/tenant1",
			metadata: .protectedResource,
			expectedURL:
				"https://rs.example.com:443/.well-known/oauth-protected-resource/tenant1"
		),
		.init(
			testDescription: "host case is preserved as given",
			source: "https://RS.Example.COM/tenant1",
			metadata: .protectedResource,
			expectedURL:
				"https://RS.Example.COM/.well-known/oauth-protected-resource/tenant1"
		),
		.init(
			testDescription: "authorization server issuer with a path",
			source: "https://issuer.example.com/tenant1",
			metadata: .authorizationServer(.oauth2),
			expectedURL:
				"https://issuer.example.com/.well-known/oauth-authorization-server/tenant1"
		),
		.init(
			testDescription: "authorization server issuer without a path",
			source: "https://issuer.example.com",
			metadata: .authorizationServer(.oauth2),
			expectedURL:
				"https://issuer.example.com/.well-known/oauth-authorization-server"
		),
		.init(
			testDescription: "OIDC issuer with a path appends after the path",
			source: "https://kc.example.com/realms/myrealm",
			metadata: .authorizationServer(.oidc),
			expectedURL:
				"https://kc.example.com/realms/myrealm/.well-known/openid-configuration"
		),
		.init(
			testDescription:
				"OIDC issuer with a terminating slash appends after the path",
			source: "https://kc.example.com/realms/myrealm/",
			metadata: .authorizationServer(.oidc),
			expectedURL:
				"https://kc.example.com/realms/myrealm/.well-known/openid-configuration"
		),
		.init(
			testDescription: "OIDC issuer without a path",
			source: "https://issuer.example.com",
			metadata: .authorizationServer(.oidc),
			expectedURL: "https://issuer.example.com/.well-known/openid-configuration"
		),
	]

	@Test(
		"Builds the discovery URL and keeps the identifier exactly as given",
		arguments: buildCases
	)
	func buildsDiscoveryRequest(_ testCase: BuildCase) throws {
		let source = try #require(URL(string: testCase.source))
		let identifier = try OAuth.DiscoveryIdentifier(source, for: testCase.metadata)
		#expect(identifier.discoveryURL.absoluteString == testCase.expectedURL)
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
		let metadata: OAuth.DiscoveryIdentifier.Metadata
		let expected: ExpectedRejection
	}

	static let invalidCases: [InvalidCase] = [
		.init(
			testDescription: "missing host",
			source: "https:///path",
			metadata: .protectedResource,
			expected: .missingHost
		),
		.init(
			testDescription: "missing scheme, host present",
			source: "//rs.example.com/tenant1",
			metadata: .protectedResource,
			expected: .missingScheme
		),
		.init(
			testDescription: "issuer: a query (RFC 8414 §2)",
			source: "https://as.example.com/tenant1?tenant=foo",
			metadata: .authorizationServer(.oauth2),
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "issuer (OIDC): a query",
			source: "https://as.example.com/tenant1?tenant=foo",
			metadata: .authorizationServer(.oidc),
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "resource: a fragment",
			source: "https://rs.example.com/tenant1#frag",
			metadata: .protectedResource,
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "issuer: a fragment",
			source: "https://as.example.com/tenant1#frag",
			metadata: .authorizationServer(.oauth2),
			expected: .invalidResourceIdentifier
		),
		.init(
			testDescription: "userinfo",
			source: "https://user:pw@rs.example.com/tenant1",
			metadata: .protectedResource,
			expected: .invalidResourceIdentifier
		),
	]

	@Test("Rejects malformed identifiers with the specific error", arguments: invalidCases)
	func rejectsInvalidIdentifiers(_ testCase: InvalidCase) throws {
		let source = try #require(URL(string: testCase.source))
		do {
			_ = try OAuth.DiscoveryIdentifier(source, for: testCase.metadata)
			Issue.record("expected \(testCase.expected) to be thrown")
		} catch let error as OAuth.Errors {
			#expect(testCase.expected.matches(error), "got \(error)")
		}
	}
}
