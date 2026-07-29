import Foundation
import GermConvenience
import GermConvenienceMocks
import HTTPTypes
import Testing

@testable import OAuth4Swift

@Suite("Refresh grant-type gate")
struct RefreshGateTests {
	static let tokenUrl = URL(string: "https://issuer.example.com/token")!
	static let tokenResponseBody =
		#"{"token_type":"Bearer","access_token":"new-at","expires_in":3600,"refresh_token":"new-rt"}"#

	static func metadata(grantTypes: [String]?) throws -> AuthServerMetadata {
		var json = """
			{
				"issuer": "https://issuer.example.com",
				"authorization_endpoint": "https://issuer.example.com/authorize",
				"token_endpoint": "https://issuer.example.com/token"
			"""
		if let grantTypes {
			let list = grantTypes.map { "\"\($0)\"" }.joined(separator: ",")
			json += #", "grant_types_supported": [\#(list)]"#
		}
		json += "}"
		return try JSONDecoder().decode(AuthServerMetadata.self, from: json.utf8Data)
	}

	//a server that lists grant types without refresh_token gets no request, and
	//the session survives - throwing preserves state where nil terminates
	@Test("a server without refresh_token support is skipped, not terminated")
	func gatedServerSkipsRefresh() async throws {
		let mock = MockHTTPFetcher()  //no handlers: any request would throw
		let session = try GateTestSession(
			metadata: Self.metadata(grantTypes: [
				"authorization_code", "client_credentials",
			]),
			fetcher: mock
		)

		let task = try #require(try await session.refresh())
		do {
			_ = try await task.value
			Issue.record("expected refreshNotSupported")
		} catch OAuth.Errors.refreshNotSupported {
			// expected: thrown, so the adopter preserves the previous state
		} catch GateTestSessionError.terminated {
			Issue.record("gate terminated the session instead of skipping")
		}

		#expect(await mock.requests(for: Self.tokenUrl).isEmpty)
	}

	//RFC 8414's default for an omitted grant_types_supported excludes
	//refresh_token; we deliberately read absent as unstated and attempt anyway
	@Test("omitted grant_types_supported still attempts the refresh")
	func absentMetadataAttemptsRefresh() async throws {
		let mock = await MockHTTPFetcher()
			.on(Self.tokenUrl)
			.enqueue(.success(.ok(Self.tokenResponseBody)))
		let session = try GateTestSession(
			metadata: Self.metadata(grantTypes: nil),
			fetcher: mock
		)

		let task = try #require(try await session.refresh())
		let accessToken = try await task.value

		#expect(accessToken.value == "new-at")
		#expect(await mock.requests(for: Self.tokenUrl).count == 1)
	}

	@Test("advertised refresh_token support attempts the refresh")
	func advertisedSupportAttemptsRefresh() async throws {
		let mock = await MockHTTPFetcher()
			.on(Self.tokenUrl)
			.enqueue(.success(.ok(Self.tokenResponseBody)))
		let session = try GateTestSession(
			metadata: Self.metadata(grantTypes: [
				"authorization_code", "refresh_token",
			]),
			fetcher: mock
		)

		let task = try #require(try await session.refresh())
		_ = try await task.value

		#expect(await mock.requests(for: Self.tokenUrl).count == 1)
	}
}

private enum GateTestSessionError: Error {
	case terminated
}

private struct AlwaysValidRefreshOptions: OAuth.TokenRefreshOptions {
	func validate(
		tokenResponse: TokenEndpointResponse,
		authServerMetadata: AuthServerMetadata,
		previousState: OAuth.SessionState.Snapshot
	) async throws -> Bool {
		true
	}
}

//exercises the nil-vs-throw distinction of the refresh closure contract: nil
//terminates the session, a throw preserves the previous state. Rethrows where
//the production adopter swallows the error and returns the old token - the
//preserve/terminate signal is the same, the throw is just observable here
private actor GateTestSession: OAuth.SessionCapabilities {
	nonisolated let clientId = "test-client"
	nonisolated let tokenEndpointAuthMethod = OAuth.ClientAuth.TokenEndpointMethods.none
	nonisolated let authFetcher: any HTTPFetcher

	let metadata: AuthServerMetadata
	let tokenRefreshOptions: any OAuth.TokenRefreshOptions = AlwaysValidRefreshOptions()
	var state: OAuth.SessionState

	init(metadata: AuthServerMetadata, fetcher: any HTTPFetcher) throws {
		self.metadata = metadata
		self.authFetcher = fetcher
		state = .init(
			clientId: clientId,
			issuingServer: metadata.issuer,
			dPoPState: nil,
			grantScopes: nil,
			tokenState: .mock(
				refreshToken: .mock(value: "refresh-token")
			)
		)
	}

	var authServerMetadata: AuthServerMetadata {
		get async throws { metadata }
	}

	var authToken: OAuth.AccessToken {
		get async throws { state.tokenState.accessToken }
	}

	nonisolated func authenticate(
		inputs: OAuth.ClientAuth.Inputs
	) async throws -> (FormParameters, HTTPFields) {
		var parameters = inputs.parameters
		parameters["client_id"] = [clientId]
		return (parameters, inputs.headers)
	}

	func startRefresh(
		continueCondition: (OAuth.RefreshToken?) -> Bool,
		refreshClosure:
			@escaping (
				OAuth.SessionState.Snapshot,
				OAuth.RefreshToken
			) async throws -> OAuth.SessionState.TokenState?
	) -> Task<OAuth.AccessToken, Error>? {
		guard
			let refreshToken = state.tokenState.refreshToken,
			continueCondition(refreshToken)
		else {
			return nil
		}

		let snapshot = state.snapshot
		return Task {
			guard let tokenState = try await refreshClosure(snapshot, refreshToken)
			else {
				throw GateTestSessionError.terminated
			}
			state.updated(tokenState: tokenState)
			return tokenState.accessToken
		}
	}
}
