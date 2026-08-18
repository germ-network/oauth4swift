import Foundation
import GermConvenience
import GermConvenienceMocks
import Testing

@testable import OAuth4Swift

@Suite("Discovery request URL construction")
struct DiscoveryURLTests {
	@Test("resourceDiscoveryRequest issues GET at the RFC 9728 URL")
	func protectedResourceMetadataURL() async throws {
		let resource = try #require(URL(string: "https://api.example.com/xrpc"))
		let expected = try #require(
			URL(
				string:
					"https://api.example.com/.well-known/oauth-protected-resource/xrpc"
			)
		)
		let body = #"{"resource":"https://api.example.com/xrpc"}"#

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(.success(.ok(body)))

		let metadata = try await mock.resourceDiscoveryRequest(url: resource)

		#expect(metadata?.resource == "https://api.example.com/xrpc")
		#expect(await mock.requests(for: expected).count == 1)
	}

	@Test("authServerDiscovery issues GET at the RFC 8414 URL")
	func authorizationServerMetadataURL() async throws {
		let issuer = try #require(URL(string: "https://as.example.com/tenant1"))
		let expected = try #require(
			URL(
				string:
					"https://as.example.com/.well-known/oauth-authorization-server/tenant1"
			)
		)
		let body = """
			{
			  "issuer": "https://as.example.com/tenant1",
			  "authorization_endpoint": "https://as.example.com/tenant1/oauth/authorize",
			  "token_endpoint": "https://as.example.com/tenant1/oauth/token"
			}
			"""

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(.success(.ok(body)))

		let metadata = try await mock.authServerDiscovery(endpoint: issuer)

		#expect(metadata?.issuer == "https://as.example.com/tenant1")
		#expect(await mock.requests(for: expected).count == 1)
	}
}
