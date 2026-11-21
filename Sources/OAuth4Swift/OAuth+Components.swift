//
//  OAuthComponents.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/5/26.
//

import Foundation
import GermConvenience
import GermConvenienceHTTP
import Logging

///Direct analog to oauth4web's OAuth module in providing stateless API as building blocks for a full client
extension OAuth {
	static public func processPushedAuthorizationResponse(
		response: HTTPDataResponse
	) throws -> PARResponse {
		try response
			.success(
				statusCode: 201,
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
			).unwrapped.queryItems ?? []

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

	/// Fetches an authorization server's metadata from the location `algorithm`
	/// selects. Pass the response to `processDiscoveryResponse`.
	///
	/// `algorithm` defaults to `.oauth2`, not oauth4webapi's `.oidc`; pass `.oidc`
	/// for an OpenID Connect provider that only serves `openid-configuration`.
	public static func discoveryRequest(
		issuer: URL,
		algorithm: DiscoveryAlgorithm = .oauth2,
		fetcher: HTTPFetcher
	) async throws -> HTTPDataResponse {
		try await metadataRequest(
			url: DiscoveryIdentifier(issuer, for: .authorizationServer(algorithm))
				.discoveryURL,
			fetcher: fetcher
		)
	}

	/// Validates a `discoveryRequest` response: a successful status, and an
	/// `issuer` identical to `expectedIssuer` (RFC 8414 §3.3, OIDC Discovery §4.3).
	public static func processDiscoveryResponse(
		expectedIssuer: URL,
		response: HTTPDataResponse
	) throws -> AuthServerMetadata {
		let metadata: AuthServerMetadata = try response.expectSuccess().decode()
		guard metadata.issuer == expectedIssuer.absoluteString else {
			throw Errors.discoveredIssuerMismatch(
				actual: metadata.issuer,
				expected: expectedIssuer.absoluteString
			)
		}
		return metadata
	}

	/// Fetches a protected resource's metadata (RFC 9728 §3.1). Pass the response
	/// to `processResourceDiscoveryResponse`.
	public static func resourceDiscoveryRequest(
		resource: URL,
		fetcher: HTTPFetcher
	) async throws -> HTTPDataResponse {
		try await metadataRequest(
			url: DiscoveryIdentifier(resource, for: .protectedResource).discoveryURL,
			fetcher: fetcher
		)
	}

	/// Validates a `resourceDiscoveryRequest` response: a successful status, and a
	/// `resource` identical to `expectedResource` (RFC 9728 §3.3).
	public static func processResourceDiscoveryResponse(
		expectedResource: URL,
		response: HTTPDataResponse
	) throws -> ProtectedResourceMetadata {
		let metadata: ProtectedResourceMetadata = try response.expectSuccess().decode()
		guard metadata.resource == expectedResource.absoluteString else {
			throw Errors.discoveredResourceMismatch(
				actual: metadata.resource,
				expected: expectedResource.absoluteString
			)
		}
		return metadata
	}

	/// Discovers and validates an authorization server's metadata in one call:
	/// `discoveryRequest` followed by `processDiscoveryResponse`.
	public static func discoverAuthorizationServer(
		issuer: URL,
		algorithm: DiscoveryAlgorithm = .oauth2,
		fetcher: HTTPFetcher
	) async throws -> AuthServerMetadata {
		try processDiscoveryResponse(
			expectedIssuer: issuer,
			response: await discoveryRequest(
				issuer: issuer,
				algorithm: algorithm,
				fetcher: fetcher
			)
		)
	}

	/// Discovers and validates a protected resource's metadata in one call:
	/// `resourceDiscoveryRequest` followed by `processResourceDiscoveryResponse`.
	public static func discoverProtectedResource(
		resource: URL,
		fetcher: HTTPFetcher
	) async throws -> ProtectedResourceMetadata {
		try processResourceDiscoveryResponse(
			expectedResource: resource,
			response: await resourceDiscoveryRequest(
				resource: resource, fetcher: fetcher)
		)
	}

	//should not redirect
	private static func metadataRequest(
		url: URL,
		fetcher: HTTPFetcher
	) async throws -> HTTPDataResponse {
		try await fetcher.data(for: BundledHTTPRequest(method: .get, url: url))
	}
}
