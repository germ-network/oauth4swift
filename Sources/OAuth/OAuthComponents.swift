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
		redirectURI: URL,
		expectedState: String
	) throws -> ParsedRedirect {
		// decode the params in the redirectURI
		let redirectComponents = try URLComponents(
			url: redirectURI,
			resolvingAgainstBaseURL: false
		).tryUnwrap

		//first check for iss and state and bail if not present
		guard
			let iss = redirectComponents.queryItems?.first(where: {
				$0.name == "iss"
			})?.value,
			let state = redirectComponents.queryItems?.first(where: {
				$0.name == "state"
			})?.value
		else {
			throw OAuthError.redirectMissingComponents
		}

		//check for error_description or error
		if let errorItem = redirectComponents.queryItems?.first(where: {
			$0.name == "error_description"
		}) {
			throw OAuthError.redirectError(errorItem.value ?? "")
		}

		if let errorItem = redirectComponents.queryItems?.first(where: {
			$0.name == "error"
		}) {
			throw OAuthError.redirectError(errorItem.value ?? "")
		}

		//assert we do not support insecure flows
		assert(
			redirectComponents.queryItems?.first(where: {
				$0.name == "id_token"
			})?.value == nil)
		assert(
			redirectComponents.queryItems?.first(where: {
				$0.name == "token"
			})?.value == nil)

		//finally can check for presence of code
		let authCode = redirectComponents.queryItems?.first(where: {
			$0.name == "code"
		})?.value

		guard state == expectedState else {
			throw OAuthError.stateTokenMismatch(state, expectedState)
		}

		guard iss == authServerMetadata.issuer else {
			throw
				OAuthError
				.issuingServerMismatch(iss, authServerMetadata.issuer)
		}

		return .init(
			authCode: authCode,
			issuer: iss,
			components: redirectComponents
		)
	}

	public struct ParsedRedirect {
		public let authCode: String?
		public let issuer: String

		public let components: URLComponents
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
