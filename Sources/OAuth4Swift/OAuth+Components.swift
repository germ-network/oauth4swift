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
extension OAuth {
	static public func processPushedAuthorizationResponse(
		response: HTTPDataResponse
	) throws -> PARResponse {
		let parsed =
			try response
			.success(
				code: 201,
				decodeResult: PARResponse.self,
				orError: OAuth.ErrorResponse.self
			)

		switch parsed {
		case .result(let result):
			return result
		case .error(let errorResponse, let errorCode):
			throw OAuth.Errors.oauthError(errorResponse, errorCode)
		}
	}

	static public func validateAuthResponse(
		authServerMetadata: AuthServerMetadata,
		callbackURL: URL,
		expectedState: String?
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
		expectedState: String?
	) throws -> AuthResponseParameters {
		let iss = callbackParameters.first(where: {
			$0.name == "iss"
		})?.value

		let state = callbackParameters.first(where: {
			$0.name == "state"
		})?.value

		//validate state if we have an expected state:
		if let expectedState {
			guard state == expectedState else {
				throw Errors.stateTokenMismatch(state ?? "[nil]", expectedState)
			}
		}

		// Validate iss if the authorization server requires issuer identification
		// and check that it matches the authorization server issuer if provided
		if iss == nil
			&& authServerMetadata.authorizationResponseIssParameterSupported == true
		{
			throw Errors.missingIssuer
		}

		if let iss {
			guard iss == authServerMetadata.issuer else {
				throw Errors.issuingServerMismatch(
					iss,
					authServerMetadata.issuer
				)
			}
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
				throw Errors.accessDenied
			case "invalid_request":
				throw Errors.invalidRequest
			case "invalid_scope":
				throw Errors.invalidScope
			default:
				// We do actually have error and error_description parameters, so we
				// return an error with those present.
				throw Errors.redirectError(
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

		// Return branded parameters
		return .init(callbackParameters)
	}

	public struct AuthResponseParameters {
		public let parameters: [URLQueryItem]

		public init(_ parameters: [URLQueryItem]) {
			self.parameters = parameters
		}

		subscript(name: String) -> [String] {
			return parameters.compactMap {
				if $0.name == name && $0.value != nil {
					return $0.value
				}
				return nil
			}
		}
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
				orError: OAuth.ErrorResponse.self
			)

		switch decodedResponse {
		case .result(let r):
			return r
		case .error(let e, let statusCode):
			switch e.error {
			case "invalid_request":
				throw Errors.invalidRequest
			case "invalid_response":
				throw Errors.invalidResponse
			default:
				throw Errors.oauthError(e, statusCode)
			}
		}
	}

	static func parseTokenScope(_ scope: String?, parent: [String]?) -> [String] {
		var scopes: [String] = []
		guard let scope else {
			return parent ?? []
		}

		// If the scope string is empty, then .components() would return [""] instead of []
		guard !scope.isEmpty else {
			return scopes
		}

		// Filter to remove any empty scope values:
		scopes = scope.components(separatedBy: " ").filter {
			$0 != ""
		}

		return scopes
	}
}

extension HTTPFetcher {
	//should not redirect
	public func resourceDiscoveryRequest(
		url: URL,
	) async throws -> ProtectedResourceMetadata? {
		//TODO: should properly prepend, not append
		let url = url.appending(
			path: "/.well-known/oauth-protected-resource"
		)

		let request = BundledHTTPRequest(
			request: .init(
				method: .get,
				url: url
			)
		)

		return try await performDiscovery(request: request)?
			.expectSuccess()
			.decode()

	}


	public func authServerDiscovery(endpoint: URL) async throws -> AuthServerMetadata? {
		let url = endpoint.appending(
			path: "/.well-known/oauth-authorization-server"
		)

		let request = BundledHTTPRequest(
			request: .init(
				method: .get,
				url: url
			)
		)
		return try await performDiscovery(request: request)?
			.expectSuccess()
			.decode()
	}

	//when we perform discovery, treat a 404 as a nil result
	func performDiscovery(
		request: BundledHTTPRequest
	) async throws -> HTTPDataResponse? {
		guard request.request.scheme == "https" else {
			throw OAuth.Errors.insecureScheme
		}
		let result = try await data(for: request)
		if result.response.status == .notFound {
			return nil
		}
		return result
	}
}
