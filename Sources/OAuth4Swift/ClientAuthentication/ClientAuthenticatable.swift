import Foundation
import GermConvenience

import struct HTTPTypes.HTTPFields
import struct HTTPTypes.HTTPRequest

extension OAuth.ClientAuth {
	public protocol Authenticable: Sendable {
		var tokenEndpointAuthMethod: TokenEndpointMethods { get }

		func authenticate(
			inputs: Inputs
		) async throws -> (FormParameters, HTTPFields)

		var authFetcher: HTTPFetcher { get }
	}
}

extension OAuth.ClientAuth.Authenticable {
	func authenticatedRequest(
		url: URL,
		method: HTTPRequest.Method,
		inputs: OAuth.ClientAuth.Inputs,
		retryNonce: Bool,
		endpointType: OAuth.DPoP.Endpoint
	) async throws -> HTTPDataResponse {
		let (parameters, headers) = try await authenticate(
			inputs: inputs
		)

		let request = try BundledHTTPRequest(
			method: method,
			url: url,
			headerFields: headers,
			body: parameters.data
		)

		if let dpopSigner = self as? OAuth.DPoP.Signing {
			if retryNonce {
				return
					try await dpopSigner
					.nonceRetryAuthenticated(
						request: request,
						token: nil,
						authFetcher: authFetcher,
						endpointType: endpointType
					)
			} else {
				return try await dpopSigner.authenticated(
					request: request,
					token: nil,
					fetcher: authFetcher
				)
			}

		} else {
			return try await authFetcher.data(for: request)
		}
	}
}

extension OAuth.ClientAuth.Authenticable {
	public func authorizationCodeGrantRequest(
		authServerMetadata: AuthServerMetadata,
		callbackParameters: OAuth.AuthResponseParameters,
		redirectURI: URL,
		pkceVerifier: String?,
		additionalParameters: FormParameters?,
	) async throws -> HTTPDataResponse {
		guard let code = callbackParameters["code"].first else {
			throw OAuth.Errors.missingAuthCode
		}

		var parameters = additionalParameters ?? .init()
		parameters["redirect_uri"] = [redirectURI.absoluteString]
		parameters["code"] = [code]

		if let pkceVerifier {
			parameters["code_verifier"] = [pkceVerifier]
		}

		return try await tokenEndpointRequest(
			authServerMetadata: authServerMetadata,
			grantType: .authorizationCode,
			parameters: parameters,
		)
	}

	func refreshTokenGrantRequest(
		authServerMetadata: AuthServerMetadata,
		additionalParameters: FormParameters?,
		refreshToken: OAuth.RefreshToken,
	) async throws -> HTTPDataResponse {
		var parameters = additionalParameters ?? .init()
		parameters["refresh_token"] = [refreshToken.value]

		return try await tokenEndpointRequest(
			authServerMetadata: authServerMetadata,
			grantType: .refreshToken,
			parameters: parameters,
		)
	}

	func tokenEndpointRequest(
		authServerMetadata: AuthServerMetadata,
		grantType: OAuth.GrantType,
		parameters: FormParameters,
	) async throws -> HTTPDataResponse {
		let url = try authServerMetadata.resolve(endpoint: .token)

		var parametersWithGrantType = parameters
		parametersWithGrantType["grant_type"] = [grantType.rawValue]

		let rawHeaders = HTTPFields(
			dictionaryLiteral: (.accept, HTTPContentType.json.rawValue),
			(.contentType, HTTPContentType.formUrlEncoded.rawValue),
		)

		return try await authenticatedRequest(
			url: url,
			method: .post,
			inputs: .init(
				authServerMetadata: authServerMetadata,
				parameters: parametersWithGrantType,
				headers: rawHeaders
			),
			retryNonce: true,
			endpointType: .auth
		)
	}
}
