import Foundation
import GermConvenience
import HTTPTypes
import Testing

@testable import OAuth4Swift

@Suite("Refresh error handling")
struct RefreshErrorTests {
	@Test("Preserves the session for a 503 server error")
	func serverError() async throws {
		let session = try TestSession(
			status: .serviceUnavailable,
			error: "server_error"
		)

		await expectPropagatedOAuthError(
			from: session,
			error: "server_error",
			status: .serviceUnavailable
		)
	}

	@Test("Preserves the session for temporarily unavailable")
	func temporarilyUnavailable() async throws {
		let session = try TestSession(
			status: .badRequest,
			error: "temporarily_unavailable"
		)

		await expectPropagatedOAuthError(
			from: session,
			error: "temporarily_unavailable",
			status: .badRequest
		)
	}

	@Test("Terminates the session for a 400 invalid grant")
	func invalidGrant() async throws {
		let session = try TestSession(
			status: .badRequest,
			error: "invalid_grant"
		)

		do {
			let task = try #require(try await session.refresh())
			_ = try await task.value
			Issue.record("Expected the session to terminate")
		} catch TestSessionError.terminated {
			// Expected: nil from the refresh closure terminates the session.
		} catch {
			Issue.record("Unexpected error: \(error)")
		}
	}

	@Test("Preserves the session for a 503 invalid grant")
	func invalidGrantFromServerError() async throws {
		let session = try TestSession(
			status: .serviceUnavailable,
			error: "invalid_grant"
		)

		await expectPropagatedOAuthError(
			from: session,
			error: "invalid_grant",
			status: .serviceUnavailable
		)
	}

	private func expectPropagatedOAuthError(
		from session: TestSession,
		error expectedError: String,
		status expectedStatus: HTTPResponse.Status
	) async {
		do {
			let task = try #require(try await session.refresh())
			_ = try await task.value
			Issue.record("Expected the OAuth error to propagate")
		} catch OAuth.Errors.oauthError(let errorResponse, let status) {
			#expect(errorResponse.error == expectedError)
			#expect(status == expectedStatus)
		} catch {
			Issue.record("Unexpected error: \(error)")
		}
	}
}

private enum TestSessionError: Error {
	case terminated
}

private struct FixedResponseFetcher: HTTPFetcher {
	let response: HTTPDataResponse

	func data(for request: BundledHTTPRequest) async throws -> HTTPDataResponse {
		response
	}
}

private struct ValidRefreshOptions: OAuth.TokenRefreshOptions {
	func validate(
		tokenResponse: TokenEndpointResponse,
		authServerMetadata: AuthServerMetadata,
		previousState: OAuth.SessionState.Snapshot
	) async throws -> Bool {
		true
	}
}

private actor TestSession: OAuth.SessionCapabilities {
	nonisolated let clientId = "test-client"
	nonisolated let tokenEndpointAuthMethod = OAuth.ClientAuth.TokenEndpointMethods.none
	nonisolated let authFetcher: any HTTPFetcher

	let metadata: AuthServerMetadata
	let tokenRefreshOptions: any OAuth.TokenRefreshOptions = ValidRefreshOptions()
	var state: OAuth.SessionState

	init(status: HTTPResponse.Status, error: String) throws {
		metadata = try JSONDecoder().decode(
			AuthServerMetadata.self,
			from: Data(
				#"{"issuer":"https://issuer.example.com","authorization_endpoint":"https://issuer.example.com/authorize","token_endpoint":"https://issuer.example.com/token"}"#
					.utf8
			)
		)
		authFetcher = FixedResponseFetcher(
			response: .init(
				data: Data(#"{"error":"\#(error)"}"#.utf8),
				response: .init(status: status)
			)
		)
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
				throw TestSessionError.terminated
			}
			state.updated(tokenState: tokenState)
			return tokenState.accessToken
		}
	}
}
