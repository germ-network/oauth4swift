//
//  OAuthComponents.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/5/26.
//

import Foundation
import GermConvenience

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

///Direct analog to oauth4web's OAuth module in providing stateless API as building blocks for a full client
public enum OAuthComponents {
	static public func processPushedAuthorizationResponse(
		response: HTTPDataResponse
	) throws -> PARResponse {
		let parsed =
			try response
			.success(
				code: 201,
				decodeResult: PARResponse.self,
				orError: OAuthErrorResponse.self
			)

		switch parsed {
		case .result(let result):
			return result
		case .error(let errorResponse, let errorCode):
			throw OAuthError.oauthError(errorResponse, errorCode)
		}
	}

	static public func validateAuthResponse(
		authServerMetadata: AuthServerMetadata,
		callbackURL: URL,
		expectedState: String
	) throws -> AuthResponseParameters {
		// decode the params in the callbackURL
		let callbackParameters =
			try URLComponents(
				url: callbackURL,
				resolvingAgainstBaseURL: false
			).tryUnwrap.queryItems ?? []

		return try validateAuthResponse(
			authServerMetadata: authServerMetadata,
			callbackParameters: callbackParameters,
			expectedState: expectedState
		)
	}

	static public func validateAuthResponse(
		authServerMetadata: AuthServerMetadata,
		callbackParameters: [URLQueryItem],
		expectedState: String
	) throws -> AuthResponseParameters {
		//first check that both iss and state are present, and bail if not present
		guard
			let iss = callbackParameters.first(where: {
				$0.name == "iss"
			})?.value,
			let state = callbackParameters.first(where: {
				$0.name == "state"
			})?.value
		else {
			throw OAuthError.redirectMissingComponents
		}

		//validate state and iss match our expected values:
		guard state == expectedState else {
			throw OAuthError.stateTokenMismatch(state, expectedState)
		}

		guard iss == authServerMetadata.issuer else {
			throw
				OAuthError
				.issuingServerMismatch(iss, authServerMetadata.issuer)
		}

		//handle errors from the oauth authorization code flow:
		let error = callbackParameters.first(where: {
			$0.name == "error"
		})?.value
		let errorDescription = callbackParameters.first(where: {
			$0.name == "error_description"
		})?.value

		if let error = error {
			// For invalid_request and invalid_scope, we do actually have the error
			// and errorDescription, so could provide these to the errors generated here:

			// The error should always be lowercase, but just being defensive:
			switch error.lowercased() {
			case "access_denied":
				throw OAuthError.accessDenied
			case "invalid_request":
				throw OAuthError.invalidRequest
			case "invalid_scope":
				throw OAuthError.invalidScope
			default:
				// We do actually have error and error_description parameters, so we
				// return an error with those present.
				throw OAuthError.redirectError(
					error.lowercased(), errorDescription)
			}
		}

		//assert we do not support insecure flows
		assert(
			callbackParameters.first(where: {
				$0.name == "id_token"
			})?.value == nil)
		assert(
			callbackParameters.first(where: {
				$0.name == "token"
			})?.value == nil)

		//finally can check for presence of code
		guard
			let code = callbackParameters.first(where: {
				$0.name == "code"
			})?.value
		else {
			throw OAuthError.missingAuthCode
		}

		return .init(
			code: code,
			// We've asserted iss === authServerMetadata.issuer above:
			issuer: authServerMetadata.issuer,
			parameters: callbackParameters.filter {
				$0.name != "code" && $0.name != "iss"
			}
		)
	}

	public struct AuthResponseParameters {
		public let code: String
		public let issuer: String
		public let parameters: [URLQueryItem]
	}

	static func processRefreshTokenResponse(
		response: HTTPDataResponse
	) throws -> TokenEndpointResponse {
		try processGenericAccessToken(response: response)
	}

	static func processGenericAccessToken(
		response: HTTPDataResponse
	) throws -> TokenEndpointResponse {
		let decodedResponse =
			try response
			.success(
				decodeResult: TokenEndpointResponse.self,
				orError: OAuthErrorResponse.self
			)

		switch decodedResponse {
		case .result(let r):
			return r
		case .error(let e, let statusCode):
			switch e.error {
			case "invalid_request":
				throw OAuthError.invalidRequest
			case "invalid_response":
				throw OAuthError.invalidResponse
			default:
				throw OAuthError.oauthError(e, statusCode)
			}
		}
	}
}

extension HTTPFetcher {
	//should not redirect
	public func resourceDiscoveryRequest(
		url: URL,
	) async throws -> ProtectedResourceMetadata {
		//TODO: should properly prepend, not append
		let url = url.appending(
			path: "/.well-known/oauth-protected-resource"
		)

		var request = URLRequest(url: url)
		request.httpMethod = HTTPMethod.get.rawValue
		request.setValue("application/json", forHTTPHeaderField: "accept")

		return try await performDiscovery(request: request)
			.expectSuccess()
			.decode()

	}

	public func authServerDiscovery(issuer: URL) async throws -> AuthServerMetadata {
		let url = issuer.appending(
			path: "/.well-known/oauth-authorization-server"
		)

		var request = URLRequest(url: url)
		request.httpMethod = HTTPMethod.get.rawValue
		request.setValue("application/json", forHTTPHeaderField: "accept")

		return try await performDiscovery(request: request)
			.expect(successCode: 200)
			.decode()
	}

	func performDiscovery(
		request: URLRequest
	) async throws -> HTTPDataResponse {
		guard request.url?.scheme == "https" else {
			throw OAuthError.insecureScheme
		}
		return try await data(for: request)
	}
}
