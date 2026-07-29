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

		try await expectPropagatedOAuthError(
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

		try await expectPropagatedOAuthError(
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

		let task = try #require(try await session.refresh())
		do {
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

		try await expectPropagatedOAuthError(
			from: session,
			error: "invalid_grant",
			status: .serviceUnavailable
		)
	}

	@Test("Preserves the session for an error body that isn't an OAuth error")
	func nonOAuthErrorBody() async throws {
		let session = try TestSession(
			status: .serviceUnavailable,
			body: "<html>503</html>".utf8Data
		)

		try await expectPreservedSession(from: session) { error in
			guard let httpError = error as? HTTPResponseError else {
				Issue.record("Unexpected error: \(error)")
				return
			}
			#expect(httpError.code == 503)
			#expect(httpError.bodyString == "<html>503</html>")
		}
	}

	@Test("Preserves the session for an empty error body")
	func emptyErrorBody() async throws {
		let session = try TestSession(status: .badGateway, body: Data())

		try await expectPreservedSession(from: session) { error in
			guard let httpError = error as? HTTPResponseError else {
				Issue.record("Unexpected error: \(error)")
				return
			}
			#expect(httpError.code == 502)
		}
	}

	//invalid_request means the request was malformed, not that the grant is gone
	@Test("Preserves the session for a 400 invalid request")
	func invalidRequest() async throws {
		let session = try TestSession(
			status: .badRequest,
			error: "invalid_request"
		)

		try await expectPreservedSession(from: session) { error in
			guard case OAuth.Errors.invalidRequest = error else {
				Issue.record("Unexpected error: \(error)")
				return
			}
		}
	}

	//TokenRefreshOptions documents a throw as "couldn't resolve validity", which
	//covers transient failures in an online check
	@Test("Preserves the session when validation can't be resolved")
	func unresolvableValidation() async throws {
		let session = try TestSession(validating: .unresolvable)

		try await expectPreservedSession(from: session) { error in
			guard case TestSessionError.offline = error else {
				Issue.record("Unexpected error: \(error)")
				return
			}
		}
	}

	@Test("Terminates the session when validation fails")
	func failedValidation() async throws {
		let session = try TestSession(validating: .invalid)

		let task = try #require(try await session.refresh())
		do {
			_ = try await task.value
			Issue.record("Expected the session to terminate")
		} catch TestSessionError.terminated {
			// Expected: an invalid token response terminates the session.
		} catch {
			Issue.record("Unexpected error: \(error)")
		}
	}

	private func expectPropagatedOAuthError(
		from session: TestSession,
		error expectedError: String,
		status expectedStatus: HTTPResponse.Status
	) async throws {
		try await expectPreservedSession(from: session) { error in
			guard
				case OAuth.Errors.oauthError(let errorResponse, let status) = error
			else {
				Issue.record("Unexpected error: \(error)")
				return
			}
			#expect(errorResponse.error == expectedError)
			#expect(status == expectedStatus)
		}
	}

	//the session survives when the refresh closure propagates rather than
	//returning nil, which is what the session implementation treats as terminal
	private func expectPreservedSession(
		from session: TestSession,
		matching assert: (any Error) -> Void
	) async throws {
		let task = try #require(try await session.refresh())
		do {
			_ = try await task.value
			Issue.record("Expected the refresh error to propagate")
		} catch TestSessionError.terminated {
			Issue.record("Expected the session to be preserved")
		} catch {
			assert(error)
		}
	}
}

private enum TestSessionError: Error {
	case terminated
	case offline
}

private struct FixedResponseFetcher: HTTPFetcher {
	let response: HTTPDataResponse

	func data(for request: BundledHTTPRequest) async throws -> HTTPDataResponse {
		response
	}
}

private struct StubRefreshOptions: OAuth.TokenRefreshOptions {
	enum Outcome {
		case valid
		case invalid
		case unresolvable
	}

	let outcome: Outcome

	init(_ outcome: Outcome = .valid) {
		self.outcome = outcome
	}

	func validate(
		tokenResponse: TokenEndpointResponse,
		authServerMetadata: AuthServerMetadata,
		previousState: OAuth.SessionState.Snapshot
	) async throws -> Bool {
		switch outcome {
		case .valid: true
		case .invalid: false
		case .unresolvable: throw TestSessionError.offline
		}
	}
}

private actor TestSession: OAuth.SessionCapabilities {
	nonisolated let clientId = "test-client"
	nonisolated let tokenEndpointAuthMethod = OAuth.ClientAuth.TokenEndpointMethods.none
	nonisolated let authFetcher: any HTTPFetcher

	let metadata: AuthServerMetadata
	let tokenRefreshOptions: any OAuth.TokenRefreshOptions
	var state: OAuth.SessionState

	init(status: HTTPResponse.Status, error: String) throws {
		try self.init(status: status, body: Data(#"{"error":"\#(error)"}"#.utf8))
	}

	//a token endpoint response the client accepts, so the refresh reaches validation
	init(validating outcome: StubRefreshOptions.Outcome) throws {
		try self.init(
			status: .ok,
			body: Data(
				#"{"access_token":"new-access-token","token_type":"DPoP","refresh_token":"new-refresh-token"}"#
					.utf8
			),
			refreshOptions: .init(outcome)
		)
	}

	init(
		status: HTTPResponse.Status,
		body: Data,
		refreshOptions: StubRefreshOptions = .init()
	) throws {
		tokenRefreshOptions = refreshOptions
		metadata = try JSONDecoder().decode(
			AuthServerMetadata.self,
			from: Data(
				#"{"issuer":"https://issuer.example.com","authorization_endpoint":"https://issuer.example.com/authorize","token_endpoint":"https://issuer.example.com/token"}"#
					.utf8
			)
		)
		authFetcher = FixedResponseFetcher(
			response: .init(
				data: body,
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
