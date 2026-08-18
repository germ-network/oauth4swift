//
//  OAuthComponents.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/5/26.
//

import Foundation
import GermConvenience
import Logging

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

///Direct analog to oauth4web's OAuth module in providing stateless API as building blocks for a full client
extension OAuth {
	static public func processPushedAuthorizationResponse(
		response: HTTPDataResponse
	) throws -> PARResponse {
		try response
			.success(
				code: 201,
				decodeResult: PARResponse.self,
				orError: OAuth.ErrorResponse.self
			)
			.get { errorResponse, errorCode in
				OAuth.Errors.oauthError(errorResponse, errorCode)
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
		try response
			.success(
				decodeResult: TokenEndpointResponse.self,
				orError: OAuth.ErrorResponse.self
			)
			.get { e, statusCode in
				switch e.error {
				case "invalid_request": Errors.invalidRequest
				case "invalid_response": Errors.invalidResponse
				default: Errors.oauthError(e, statusCode)
				}
			}
	}

	//if no scopes are passed back, then we get the parent (requested or granted)
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

		if let parent, !parent.isEmpty {
			if !Set(parent).isSuperset(of: scopes) {
				Logger(label: "parseTokenScope").error(
					"Requested scopes \(parent) but received \(scopes)"
				)
			}
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

		let request = try BundledHTTPRequest(
			method: .get,
			url: url,
		)

		return try await performDiscovery(request: request)?
			.expectSuccess()
			.decode()

	}

	public func authServerDiscovery(endpoint: URL) async throws -> AuthServerMetadata? {
		let url = endpoint.appending(
			path: "/.well-known/oauth-authorization-server"
		)

		let request = try BundledHTTPRequest(
			method: .get,
			url: url,
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

extension OAuth {
	// RFC 9728 Section 3.1 — Protected Resource Metadata well-known suffix.
	static let wellKnownProtectedResource = ".well-known/oauth-protected-resource"
	// RFC 8414 Section 3.1 — Authorization Server Metadata well-known suffix.
	static let wellKnownAuthorizationServer = ".well-known/oauth-authorization-server"
}

extension URL {
	/// Builds a `.well-known` discovery URL by inserting the given segment
	/// between the host and the existing path, per RFC 9728 §3.1 and RFC 8414 §3.1.
	/// Any terminating `/` on the source path is stripped before inserting the
	/// well-known segment so that trailing-slash and no-slash variants of the
	/// same origin resolve to the same RFC-compliant metadata URL.
	/// Preserves the original path's percent-encoding, port, and query; drops the fragment.
	func insertingWellKnownSegment(_ segment: String) throws -> URL {
		guard
			var components = URLComponents(url: self, resolvingAgainstBaseURL: false),
			let host = components.host, !host.isEmpty,
			components.scheme != nil
		else {
			throw OAuth.Errors.missingScheme
		}
		var existingPath = components.percentEncodedPath
		while existingPath.hasSuffix("/") {
			existingPath.removeLast()
		}
		components.percentEncodedPath = "/" + segment + existingPath
		components.fragment = nil
		return try components.url.tryUnwrap(OAuth.Errors.missingScheme)
	}
}
