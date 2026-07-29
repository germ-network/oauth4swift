import Foundation
import GermConvenience
import GermConvenienceMocks
import HTTPTypes
import Testing

@testable import OAuth4Swift

@Suite("Token revocation") struct RevocationTests {
	static let revokeUrl = URL(string: "https://as.example/oauth/revoke")!

	struct TestClient: OAuth.ClientAuth.Authenticable {
		let clientAuth = OAuth.ClientAuth.None()
		let authFetcher: HTTPFetcher

		var tokenEndpointAuthMethod: OAuth.ClientAuth.TokenEndpointMethods {
			clientAuth.tokenEndpointAuthMethod
		}

		func authenticate(
			inputs: OAuth.ClientAuth.Inputs
		) async throws -> (FormParameters, HTTPFields) {
			try await clientAuth.authenticate(clientId: "test-client", inputs: inputs)
		}
	}

	static func metadata(revocationEndpoint: Bool) throws -> AuthServerMetadata {
		var json = """
			{
				"issuer": "https://as.example",
				"authorization_endpoint": "https://as.example/oauth/authorize",
				"token_endpoint": "https://as.example/oauth/token"
			"""
		if revocationEndpoint {
			json += #", "revocation_endpoint": "https://as.example/oauth/revoke""#
		}
		json += "}"
		return try JSONDecoder().decode(AuthServerMetadata.self, from: json.utf8Data)
	}

	static let accessToken = OAuth.AccessToken(value: "at-123", expiry: nil, fetchedOn: nil)
	static let refreshToken = OAuth.RefreshToken(value: "rt-456", expiry: nil, fetchedOn: nil)

	@Test("revoking an access token sends the RFC 7009 form body")
	func accessTokenWireFormat() async throws {
		let mock = await MockHTTPFetcher()
			.on(Self.revokeUrl)
			.enqueue(.success(.ok()))

		try await TestClient(authFetcher: mock).revocationRequest(
			authServerMetadata: Self.metadata(revocationEndpoint: true),
			token: Self.accessToken
		)

		let request = try await mock.firstRequest(for: Self.revokeUrl)
		#expect(request.request.method == .post)
		#expect(
			request.request.headerFields[.contentType]?.hasPrefix(
				"application/x-www-form-urlencoded") == true)

		let body = FormParameters(parsing: request.body ?? Data())
		#expect(body["token"] == ["at-123"])
		#expect(body["token_type_hint"] == ["access_token"])
		#expect(body["client_id"] == ["test-client"])
	}

	@Test("revoking a refresh token sends the refresh_token hint")
	func refreshTokenHint() async throws {
		let mock = await MockHTTPFetcher()
			.on(Self.revokeUrl)
			.enqueue(.success(.ok()))

		try await TestClient(authFetcher: mock).revocationRequest(
			authServerMetadata: Self.metadata(revocationEndpoint: true),
			token: Self.refreshToken
		)

		let body = FormParameters(
			parsing: try await mock.firstRequest(for: Self.revokeUrl).body ?? Data())
		#expect(body["token"] == ["rt-456"])
		#expect(body["token_type_hint"] == ["refresh_token"])
	}

	@Test("an OAuth error body throws oauthError with the status")
	func oauthErrorBody() async throws {
		let mock = await MockHTTPFetcher()
			.on(Self.revokeUrl)
			.enqueue(
				.success(
					.status(
						.badRequest,
						data: #"{"error":"unsupported_token_type"}"#
							.utf8Data)))

		let thrown = try await #require(
			#expect(throws: OAuth.Errors.self) {
				try await TestClient(authFetcher: mock).revocationRequest(
					authServerMetadata: Self.metadata(revocationEndpoint: true),
					token: Self.accessToken
				)
			})

		guard case .oauthError(let body, let status) = thrown else {
			Issue.record("expected .oauthError, got \(thrown)")
			return
		}
		#expect(body.error == "unsupported_token_type")
		#expect(status.code == 400)
	}

	@Test("a non-OAuth error body preserves the status and bytes")
	func nonOAuthErrorBody() async throws {
		let mock = await MockHTTPFetcher()
			.on(Self.revokeUrl)
			.enqueue(.success(.status(.badGateway, data: "<html>502</html>".utf8Data)))

		let thrown = try await #require(
			#expect(throws: HTTPResponseError.self) {
				try await TestClient(authFetcher: mock).revocationRequest(
					authServerMetadata: Self.metadata(revocationEndpoint: true),
					token: Self.accessToken
				)
			})

		#expect(thrown.code == 502)
		#expect(thrown.bodyString == "<html>502</html>")
	}

	//documented contract: no advertised revocation endpoint means no network
	//call and no error - the caller cannot distinguish "revoked" from "server
	//cannot revoke"
	@Test("no advertised revocation endpoint is a silent no-op")
	func noEndpointNoOp() async throws {
		let mock = MockHTTPFetcher()  //no handlers - any request would throw

		try await TestClient(authFetcher: mock).revocationRequest(
			authServerMetadata: Self.metadata(revocationEndpoint: false),
			token: Self.accessToken
		)

		#expect(await mock.requests(for: Self.revokeUrl).isEmpty)
	}
}
