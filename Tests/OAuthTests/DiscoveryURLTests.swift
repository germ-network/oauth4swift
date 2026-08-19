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

	@Test("resourceDiscoveryRequest issues GET at the RFC 9728 URL for a path-less resource")
	func protectedResourceMetadataURLNoPath() async throws {
		let resource = try #require(URL(string: "https://api.example.com"))
		let expected = try #require(
			URL(string: "https://api.example.com/.well-known/oauth-protected-resource")
		)
		let body = #"{"resource":"https://api.example.com"}"#

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(.success(.ok(body)))

		let metadata = try await mock.resourceDiscoveryRequest(url: resource)

		#expect(metadata?.resource == "https://api.example.com")
		#expect(await mock.requests(for: expected).count == 1)
	}

	@Test(
		"authServerDiscovery falls back to the legacy appended URL on a 404 at the RFC location"
	)
	func authorizationServerMetadataLegacyFallback() async throws {
		let issuer = try #require(URL(string: "https://as.example.com/tenant1"))
		let rfcURL = try #require(
			URL(
				string:
					"https://as.example.com/.well-known/oauth-authorization-server/tenant1"
			)
		)
		let legacyURL = try #require(
			URL(
				string:
					"https://as.example.com/tenant1/.well-known/oauth-authorization-server"
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
			.on(rfcURL, method: .get)
			.enqueue(.success(.status(.notFound)))
		await mock.on(legacyURL, method: .get).enqueue(.success(.ok(body)))

		let metadata = try await mock.authServerDiscovery(endpoint: issuer)

		#expect(metadata?.issuer == "https://as.example.com/tenant1")
		#expect(await mock.requests(for: rfcURL).count == 1)
		#expect(await mock.requests(for: legacyURL).count == 1)
	}

	@Test("authServerDiscovery returns nil when both the RFC and legacy locations 404")
	func authorizationServerMetadataBoth404() async throws {
		let issuer = try #require(URL(string: "https://as.example.com/tenant1"))
		let rfcURL = try #require(
			URL(
				string:
					"https://as.example.com/.well-known/oauth-authorization-server/tenant1"
			)
		)
		let legacyURL = try #require(
			URL(
				string:
					"https://as.example.com/tenant1/.well-known/oauth-authorization-server"
			)
		)

		let mock = await MockHTTPFetcher()
			.on(rfcURL, method: .get)
			.enqueue(.success(.status(.notFound)))
		await mock.on(legacyURL, method: .get).enqueue(.success(.status(.notFound)))

		let metadata = try await mock.authServerDiscovery(endpoint: issuer)

		#expect(metadata == nil)
	}

	@Test(
		"authServerDiscovery throws when the discovered issuer does not match the requested identifier"
	)
	func authorizationServerMetadataIssuerMismatch() async throws {
		let issuer = try #require(URL(string: "https://as.example.com/tenant1"))
		let expected = try #require(
			URL(
				string:
					"https://as.example.com/.well-known/oauth-authorization-server/tenant1"
			)
		)
		let body = """
			{
			  "issuer": "https://attacker.example.com",
			  "authorization_endpoint": "https://as.example.com/tenant1/oauth/authorize",
			  "token_endpoint": "https://as.example.com/tenant1/oauth/token"
			}
			"""

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(.success(.ok(body)))

		await #expect(throws: OAuth.Errors.self) {
			try await mock.authServerDiscovery(endpoint: issuer)
		}
	}

	@Test(
		"resourceDiscoveryRequest throws when the discovered resource does not match the requested identifier"
	)
	func protectedResourceMetadataResourceMismatch() async throws {
		let resource = try #require(URL(string: "https://api.example.com/xrpc"))
		let expected = try #require(
			URL(
				string:
					"https://api.example.com/.well-known/oauth-protected-resource/xrpc"
			)
		)
		let body = #"{"resource":"https://attacker.example.com"}"#

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(.success(.ok(body)))

		await #expect(throws: OAuth.Errors.self) {
			try await mock.resourceDiscoveryRequest(url: resource)
		}
	}
}
