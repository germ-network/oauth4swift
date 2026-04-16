import Foundation
import GermConvenience
import HTTPTypes

extension OAuth {
	public protocol ClientAuthenticatable: Sendable {
		var tokenEndpointAuthMethod: TokenEndpointMethods { get }

		func authenticate(
			inputs: ClientAuthInputs
		) async throws -> (FormParameters, HTTPFields)

		var authFetcher: HTTPFetcher { get }
		var clientAuthArchive: Data? { get async }
	}
}

extension OAuth.ClientAuthenticatable {
	func authenticatedRequest(
		url: URL,
		method: HTTPRequest.Method,
		inputs: OAuth.ClientAuthInputs,
		retry: Bool
	) async throws -> HTTPDataResponse {
		let (parameters, headers) = try await authenticate(
			inputs: inputs
		)

		let request = try BundledHTTPRequest(
			request: .init(
				method: method,
				url: url,
				headerFields: headers
			),
			body: parameters.data
		)

		if let dpopSigner = self as? DPoPSigning {
			if retry {
				return
					try await dpopSigner
					.nonceRetryAuthenticated(
						request: request,
						token: nil,
						authFetcher: authFetcher
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

extension OAuth.ClientAuthenticatable {
	public func authorizationCodeGrantRequest(
		authServerMetadata: AuthServerMetadata,
		callbackParameters: OAuth.AuthResponseParameters,
		redirectURI: URL,
		pkceVerifier: String?,
		additionalParameters: [String: String],
	) async throws -> HTTPDataResponse {
		guard let code = callbackParameters["code"].first else {
			throw OAuth.Errors.missingAuthCode
		}

		var parameters = FormParameters(additionalParameters)
		parameters["redirect_uri"] = redirectURI.absoluteString
		parameters["code"] = code

		if let pkceVerifier {
			parameters["code_verifier"] = pkceVerifier
		}

		return try await tokenEndpointRequest(
			authServerMetadata: authServerMetadata,
			grantType: .authorizationCode,
			parameters: parameters,
		)
	}

	func refreshTokenGrantRequest(
		authServerMetadata: AuthServerMetadata,
		additionalParameters: [String: String],
		refreshToken: String,
	) async throws -> HTTPDataResponse {
		var parameters = FormParameters(additionalParameters)
		parameters["refresh_token"] = refreshToken

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
		parametersWithGrantType["grant_type"] = grantType.rawValue

		let (formHeader, _) = HTTPContentType.formEncoded
		let rawHeaders = HTTPFields(
			dictionaryLiteral: (.accept, HTTPContentType.json.rawValue),
			(.contentType, formHeader),
		)

		return try await authenticatedRequest(
			url: url,
			method: .post,
			inputs: .init(
				authServerMetadata: authServerMetadata,
				parameters: parametersWithGrantType,
				headers: rawHeaders
			),
			retry: false
		)
	}
}
