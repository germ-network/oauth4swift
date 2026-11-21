import Foundation
import Testing

@testable import OAuth4Swift

@Suite("DPoP htu construction (RFC 9449 §4.2)")
struct DPoPTargetURITests {
	@Test(
		"targetURI strips query and fragment, normalizes origin and keeps path encoding",
		arguments: [
			("https://example.com/token?a=b#frag", "https://example.com/token"),
			("https://example.com", "https://example.com/"),
			("https://example.com:443/token", "https://example.com/token"),
			("http://example.com:80/token", "http://example.com/token"),
			("https://example.com:8443/token", "https://example.com:8443/token"),
			("HTTPS://example.com/token", "https://example.com/token"),
			("https://user:pass@example.com/token", "https://example.com/token"),
			("https://example.com/a%2Fb", "https://example.com/a%2Fb"),
		]
	)
	func targetURI(input: String, expected: String) throws {
		let url = try #require(URL(string: input))
		#expect(try OAuth.DPoP.RequestPayload.targetURI(of: url) == expected)
	}

	@Test("targetURI throws for a URL without a host")
	func targetURIWithoutHost() throws {
		let url = try #require(URL(string: "urn:example:token"))
		#expect(throws: (any Error).self) {
			try OAuth.DPoP.RequestPayload.targetURI(of: url)
		}
	}
}
