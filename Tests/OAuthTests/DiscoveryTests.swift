import Foundation
import GermConvenience
import GermConvenienceHTTP
import GermConvenienceMocks
import Testing

@testable import OAuth4Swift

@Suite("Discovery requests and response processing")
struct DiscoveryTests {
	static func authServerBody(issuer: String) -> String {
		"""
		{
		  "issuer": "\(issuer)",
		  "authorization_endpoint": "\(issuer)/oauth/authorize",
		  "token_endpoint": "\(issuer)/oauth/token"
		}
		"""
	}

	@Test("resourceDiscoveryRequest issues GET at the RFC 9728 URL")
	func protectedResourceMetadataURL() async throws {
		let resource = try #require(URL(string: "https://rs.example.com/tenant1"))
		let expected = try #require(
			URL(
				string:
					"https://rs.example.com/.well-known/oauth-protected-resource/tenant1"
			)
		)
		let body = #"{"resource":"https://rs.example.com/tenant1"}"#

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(.success(.ok(body)))

		let response = try await OAuth.resourceDiscoveryRequest(
			resource: resource,
			fetcher: mock
		)
		let metadata = try OAuth.processResourceDiscoveryResponse(
			expectedResource: resource,
			response: response
		)

		#expect(metadata.resource == "https://rs.example.com/tenant1")
		#expect(await mock.requests(for: expected).count == 1)
	}

	@Test("resourceDiscoveryRequest issues GET at the RFC 9728 URL for a path-less resource")
	func protectedResourceMetadataURLNoPath() async throws {
		let resource = try #require(URL(string: "https://rs.example.com"))
		let expected = try #require(
			URL(string: "https://rs.example.com/.well-known/oauth-protected-resource")
		)
		let body = #"{"resource":"https://rs.example.com"}"#

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(.success(.ok(body)))

		let response = try await OAuth.resourceDiscoveryRequest(
			resource: resource,
			fetcher: mock
		)
		let metadata = try OAuth.processResourceDiscoveryResponse(
			expectedResource: resource,
			response: response
		)

		#expect(metadata.resource == "https://rs.example.com")
		#expect(await mock.requests(for: expected).count == 1)
	}

	@Test("discoveryRequest issues GET at the RFC 8414 URL")
	func authorizationServerMetadataURL() async throws {
		let issuer = try #require(URL(string: "https://as.example.com/tenant1"))
		let expected = try #require(
			URL(
				string:
					"https://as.example.com/.well-known/oauth-authorization-server/tenant1"
			)
		)

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(
				.success(
					.ok(
						Self.authServerBody(
							issuer: "https://as.example.com/tenant1")))
			)

		let response = try await OAuth.discoveryRequest(issuer: issuer, fetcher: mock)
		let metadata = try OAuth.processDiscoveryResponse(
			expectedIssuer: issuer,
			response: response
		)

		#expect(metadata.issuer == "https://as.example.com/tenant1")
		#expect(await mock.requests(for: expected).count == 1)
	}

	@Test("discoveryRequest with the oidc algorithm issues GET at the OIDC Discovery URL")
	func authorizationServerMetadataOIDCLocation() async throws {
		let issuer = try #require(URL(string: "https://kc.example.com/realms/myrealm"))
		let expected = try #require(
			URL(
				string:
					"https://kc.example.com/realms/myrealm/.well-known/openid-configuration"
			)
		)

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(
				.success(
					.ok(
						Self.authServerBody(
							issuer:
								"https://kc.example.com/realms/myrealm"
						))
				)
			)

		let response = try await OAuth.discoveryRequest(
			issuer: issuer,
			algorithm: .oidc,
			fetcher: mock
		)
		let metadata = try OAuth.processDiscoveryResponse(
			expectedIssuer: issuer,
			response: response
		)

		#expect(metadata.issuer == "https://kc.example.com/realms/myrealm")
		#expect(await mock.requests(for: expected).count == 1)
	}

	@Test("processDiscoveryResponse throws on a 404, and no other location is tried")
	func authorizationServerMetadata404() async throws {
		let issuer = try #require(URL(string: "https://as.example.com/tenant1"))
		let expected = try #require(
			URL(
				string:
					"https://as.example.com/.well-known/oauth-authorization-server/tenant1"
			)
		)

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(.success(.status(.notFound)))

		let response = try await OAuth.discoveryRequest(issuer: issuer, fetcher: mock)

		#expect(throws: (any Error).self) {
			try OAuth.processDiscoveryResponse(
				expectedIssuer: issuer, response: response)
		}
		#expect(await mock.requests(for: expected).count == 1)
	}

	@Test("discoveryRequest refuses a non-https issuer")
	func authorizationServerMetadataInsecureScheme() async throws {
		let issuer = try #require(URL(string: "http://as.example.com"))
		let mock = MockHTTPFetcher()

		await #expect(throws: OAuth.Errors.self) {
			try await OAuth.discoveryRequest(issuer: issuer, fetcher: mock)
		}
	}

	@Test(
		"processDiscoveryResponse rejects issuers that are not identical to the expected issuer",
		arguments: [
			("https://as.example.com/tenant1", "https://attacker.example.com"),
			("https://AS.Example.com:443/tenant1", "https://as.example.com/tenant1"),
			("https://as.example.com/tenant1/", "https://as.example.com/tenant1"),
		]
	)
	func authorizationServerMetadataIssuerMismatch(
		expectedIssuer: String,
		claimedIssuer: String
	) throws {
		let issuer = try #require(URL(string: expectedIssuer))
		let response = HTTPDataResponse.ok(Self.authServerBody(issuer: claimedIssuer))

		#expect(throws: OAuth.Errors.self) {
			try OAuth.processDiscoveryResponse(
				expectedIssuer: issuer, response: response)
		}
	}

	@Test(
		"processResourceDiscoveryResponse rejects a resource that is not identical to the expected resource"
	)
	func protectedResourceMetadataResourceMismatch() throws {
		let resource = try #require(URL(string: "https://rs.example.com/tenant1"))
		let response = HTTPDataResponse.ok(#"{"resource":"https://attacker.example.com"}"#)

		#expect(throws: OAuth.Errors.self) {
			try OAuth.processResourceDiscoveryResponse(
				expectedResource: resource,
				response: response
			)
		}
	}

	@Test("discoverAuthorizationServer requests and validates in one call")
	func discoverAuthorizationServer() async throws {
		let issuer = try #require(URL(string: "https://kc.example.com/realms/myrealm"))
		let expected = try #require(
			URL(
				string:
					"https://kc.example.com/realms/myrealm/.well-known/openid-configuration"
			)
		)

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(
				.success(
					.ok(
						Self.authServerBody(
							issuer: "https://attacker.example.com"))
				)
			)

		await #expect(throws: OAuth.Errors.self) {
			try await OAuth.discoverAuthorizationServer(
				issuer: issuer,
				algorithm: .oidc,
				fetcher: mock
			)
		}
		#expect(await mock.requests(for: expected).count == 1)
	}

	@Test("discoverProtectedResource requests and validates in one call")
	func discoverProtectedResource() async throws {
		let resource = try #require(URL(string: "https://rs.example.com/tenant1"))
		let expected = try #require(
			URL(
				string:
					"https://rs.example.com/.well-known/oauth-protected-resource/tenant1"
			)
		)
		let body = #"{"resource":"https://rs.example.com/tenant1"}"#

		let mock = await MockHTTPFetcher()
			.on(expected, method: .get)
			.enqueue(.success(.ok(body)))

		let metadata = try await OAuth.discoverProtectedResource(
			resource: resource,
			fetcher: mock
		)

		#expect(metadata.resource == "https://rs.example.com/tenant1")
		#expect(await mock.requests(for: expected).count == 1)
	}
}
