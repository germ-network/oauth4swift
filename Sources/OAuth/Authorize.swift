//
//  Authorize.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/8/26.
//

import Foundation
import GermConvenience
import Logging

//for authorize
public struct AuthorizeInputs {
	let clientMetadata: OAuthClient
	let requestedScopes: [String]
	let stateToken: String
	let pkceVerifier: PKCEVerifier
	let parConfig: PARConfiguration?
	let issuer: URL

	public init(
		clientMetadata: OAuthClient,
		scopes: [String]?,
		stateToken: String = UUID().uuidString,
		pkceVerifier: PKCEVerifier = .init(),
		parConfig: PARConfiguration?,
		issuer: URL
	) {
		self.clientMetadata = clientMetadata
		self.stateToken = stateToken
		self.pkceVerifier = pkceVerifier
		self.parConfig = parConfig
		self.issuer = issuer

		if let scopes {
			self.requestedScopes = scopes
		} else {
			self.requestedScopes = clientMetadata.scopes
		}
	}
}

///Client defined paramenters for requests to the Auth server, for refresh and user auth requests.
///does not include the issuer so that it can be lazily fetched
public struct AuthServerRequestOptions: Sendable {
	let additionalParameters: [String: String]
	let authFetcher: HTTPFetcher
	let tokenValidator:
		@Sendable (AuthServerMetadata, TokenEndpointResponse) throws -> SessionState.Mutable
	let dpopSigner: DPoPSigning?

	public init(
		additionalParameters: [String: String],
		authFetcher: HTTPFetcher,
		tokenValidator:
			@escaping @Sendable (
				AuthServerMetadata,
				TokenEndpointResponse
			) throws -> SessionState.Mutable,
		dpopSigner: DPoPSigning?
	) {
		self.additionalParameters = additionalParameters
		self.authFetcher = authFetcher
		self.tokenValidator = tokenValidator
		self.dpopSigner = dpopSigner
	}

	public func performUserAuthentication(
		authorizeInputs: AuthorizeInputs,
		userAuthenticator: UserAuthenticator,
	) async throws -> SessionState.Archive {
		let clientId = authorizeInputs.clientMetadata.clientId
		let challenge = authorizeInputs.pkceVerifier.challenge
		let scopes = authorizeInputs.requestedScopes.joined(separator: " ")

		let authServerMetadata = try await authFetcher.authServerDiscovery(
			issuer: authorizeInputs.issuer
		)

		if let parConfig = authorizeInputs.parConfig {
			let parParams = [
				"client_id": clientId,
				"state": authorizeInputs.stateToken,
				"scope": scopes,
				"response_type": "code",
				"redirect_uri": authorizeInputs.clientMetadata.redirectURI
					.absoluteString,
				"code_challenge": challenge.value,
				"code_challenge_method": challenge.method,
			].merging(parConfig.parameters, uniquingKeysWith: { a, b in a })

			let parHTTPResponse = try await pushedAuthorizationRequest(
				authServerMetadata: authServerMetadata,
				clientMetadata: authorizeInputs.clientMetadata,
				params: parParams,
				headers: [:],
			)

			let parResponse = try OAuthComponents.processPushedAuthorizationResponse(
				response: parHTTPResponse
			)

			let tokenURL = try Self.authorizationURL(
				authEndpoint: authServerMetadata.authorizationEndpoint,
				parRequestURI: parResponse.requestURI,
				clientId: clientId
			)

			let scheme = try authorizeInputs.clientMetadata.redirectURIScheme

			let callbackURL = try await userAuthenticator(tokenURL, scheme)

			return try await finishAuthorization(
				callbackURL: callbackURL,
				authInputs: authorizeInputs,
				authServerMetadata: authServerMetadata,
			)
		} else {
			throw OAuthError.notImplemented
		}
	}

	func pushedAuthorizationRequest(
		authServerMetadata: AuthServerMetadata,
		clientMetadata: OAuthClient,
		params: [String: String],
		headers: [String: String],
	) async throws -> HTTPDataResponse {
		let parEndpoint = try authServerMetadata.resolve(
			endpoint: .par)

		var bodyParams = params
		bodyParams["client_id"] = clientMetadata.clientId

		var headers = headers
		headers["accept"] = "application/json"
		headers["content-type"] = "application/x-www-form-urlencoded;charset=UTF-8"

		var request = URLRequest(url: parEndpoint)
		for (key, value) in headers {
			request.setValue(value, forHTTPHeaderField: key)
		}
		request.httpMethod = HTTPMethod.post.rawValue
		request.httpBody = bodyParams.urlEncodedHTTPBody

		if let dpopSigner {
			return try await dpopSigner.nonceRetryAuthenticated(
				request: request,
				token: nil,
				authFetcher: authFetcher
			)
		} else {
			return try await authFetcher.data(for: request)
		}
	}

	static private func authorizationURL(
		authEndpoint: URL,
		parRequestURI: String,
		clientId: String,
	) throws -> URL {
		var components = URLComponents(url: authEndpoint, resolvingAgainstBaseURL: false)

		components?.queryItems = [
			URLQueryItem(name: "request_uri", value: parRequestURI),
			URLQueryItem(name: "client_id", value: clientId),
		]

		return try (components?.url).tryUnwrap
	}

	func finishAuthorization(
		callbackURL: URL,
		authInputs: AuthorizeInputs,
		authServerMetadata: AuthServerMetadata,
	) async throws -> SessionState.Archive {
		let callbackParameters = try OAuthComponents.validateAuthResponse(
			authServerMetadata: authServerMetadata,
			callbackURL: callbackURL,
			expectedState: authInputs.stateToken
		)

		let httpResponse = try await authorizationCodeGrantRequest(
			authServerMetadata: authServerMetadata,
			redirectURI: authInputs.clientMetadata.redirectURI,
			callbackParameters: callbackParameters,
			pkceVerifier: authInputs.pkceVerifier.verifier,
			additionalParameters: additionalParameters,
		)

		let (tokenResponse, additionalParams) = try processAuthorizationCodeOAuth2Response(
			authServerMetadata: authServerMetadata,
			response: httpResponse
		)

		return .init(
			dPopKey: try await dpopSigner?.dpopKey,
			additionalParams: additionalParams,
			mutable: tokenResponse
		)
	}

	public func authorizationCodeGrantRequest(
		authServerMetadata: AuthServerMetadata,
		redirectURI: URL,
		callbackParameters: OAuthComponents.AuthResponseParameters,
		pkceVerifier: String?,
		additionalParameters: [String: String],
	) async throws -> HTTPDataResponse {
		guard let code = callbackParameters["code"].first else {
			throw OAuthError.missingAuthCode
		}

		var parameters = additionalParameters
		parameters["redirect_uri"] = redirectURI.absoluteString
		parameters["code"] = code

		if let pkceVerifier {
			parameters["code_verifier"] = pkceVerifier
		}

		return try await tokenEndpointRequest(
			authServerMetadata: authServerMetadata,
			grantType: .authorizationCode,
			parameters: parameters,
			headers: [:],
		)
	}

	func processAuthorizationCodeOAuth2Response(
		authServerMetadata: AuthServerMetadata,
		response: HTTPDataResponse
	) throws -> (SessionState.Mutable, [String: String]?) {
		let tokenResponse = try OAuthComponents.processGenericAccessToken(
			response: response)

		//check the claims
		let sessionState = try tokenValidator(authServerMetadata, tokenResponse)

		let additionalParams = tokenResponse.additionalFields?
			.compactMapValues {
				if let string = $0 as? String {
					return string
				} else {
					Logger(label: "processAuthorizationCodeOAuth2Response")
						.error("received param value \($0)")
					return nil
				}
			}

		return (sessionState, additionalParams)
	}

	func refreshTokenGrantRequest(
		authServerMetadata: AuthServerMetadata,
		refreshToken: String,
	) async throws -> HTTPDataResponse {
		var parameters = additionalParameters
		parameters["refresh_token"] = refreshToken

		return try await tokenEndpointRequest(
			authServerMetadata: authServerMetadata,
			grantType: .refreshToken,
			parameters: parameters,
			headers: [:],
		)
	}

	func tokenEndpointRequest(
		authServerMetadata: AuthServerMetadata,
		grantType: GrantType,
		parameters: [String: String],
		headers: [String: String],
	) async throws -> HTTPDataResponse {
		let url = try authServerMetadata.resolve(endpoint: .token)

		var modifiedParams = parameters
		modifiedParams["grant_type"] = grantType.rawValue

		var headers = headers
		headers["accept"] = "application/json"
		headers["content-type"] = "application/x-www-form-urlencoded;charset=UTF-8"

		var request = URLRequest(url: url)
		for (key, value) in headers {
			request.setValue(value, forHTTPHeaderField: key)
		}

		request.httpMethod = HTTPMethod.post.rawValue
		request.httpBody = modifiedParams.urlEncodedHTTPBody

		if let dpopSigner {
			return try await dpopSigner.authenticated(
				request: request,
				token: nil,
				fetcher: authFetcher
			)
		} else {
			return try await authFetcher.data(for: request)
		}
	}
}

extension [String: String] {
	var urlEncodedHTTPBody: Data {
		map({ [$0, $1].joined(separator: "=") })
			.joined(separator: "&")
			.utf8Data
	}
}
