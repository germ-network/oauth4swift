//
//  Authorize.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/8/26.
//

import Foundation
import GermConvenience
import HTTPTypes
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
		scopes: [String]? = nil,
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
	public typealias TokenValidator =
		@Sendable (
			TokenEndpointResponse,
			AuthServerMetadata,
			ImmutableSessionState?
		) async throws -> Bool

	let additionalParameters: [String: String]
	let authFetcher: HTTPFetcher
	let tokenValidator: TokenValidator
	let dpopSigner: DPoPSigning?

	public init(
		additionalParameters: [String: String],
		authFetcher: HTTPFetcher,
		tokenValidator: @escaping TokenValidator,
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
				//TODO: get these from a config
				customHeaders: [],
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
		customHeaders: [HTTPField],
	) async throws -> HTTPDataResponse {
		let parEndpoint = try authServerMetadata.resolve(
			endpoint: .par)

		var modifiedParams = params
		modifiedParams["client_id"] = clientMetadata.clientId

		let requestBody = HTTPRequestBody(
			url: parEndpoint,
			method: .post,
			httpBody: modifiedParams.urlEncodedHTTPBody,
			customHeaders: customHeaders,
			//default accept is "application/json"
			contentType: "application/x-www-form-urlencoded;charset=UTF-8",

		)

		if let dpopSigner {
			return try await dpopSigner.nonceRetryAuthenticated(
				requestBody: requestBody,
				token: nil,
				authFetcher: authFetcher
			)
		} else {
			return try await authFetcher.data(for: requestBody)
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

		let (tokenResponse, additionalParams) =
			try await processAuthorizationCodeOAuth2Response(
				authServerMetadata: authServerMetadata,
				response: httpResponse
			)

		return .init(
			client: authInputs.clientMetadata,
			dPopKey: try await dpopSigner?.dpopKey,
			issuingServer: authServerMetadata.issuer,
			additionalParams: additionalParams,
			// We save the first authorization response's scopes as the Authorization
			// Grant's scopes, in future token refresh calls, we can change scopes up
			// and down within the bounds of grantScopes.
			grantScopes: tokenResponse.scopes,
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
			//TODO: get these from a config
			customHeaders: [],
		)
	}

	func processAuthorizationCodeOAuth2Response(
		authServerMetadata: AuthServerMetadata,
		response: HTTPDataResponse
	) async throws -> (SessionState.Mutable, [String: String]?) {
		let tokenResponse = try OAuthComponents.processGenericAccessToken(
			response: response)

		//check the token response is valid, e.g., asserting the authorization
		//server can really issue the token for that `sub` parameter in the
		//tokenResponse
		if try await tokenValidator(tokenResponse, authServerMetadata, nil) == false {
			throw OAuthError.tokenInvalid
		}

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

		let sessionState = SessionState.Mutable(
			accessToken: .init(
				value: tokenResponse.accessToken, expiresIn: tokenResponse.expiresIn
			),
			refreshToken: .init(
				value: tokenResponse.refreshToken,
				timeout: tokenResponse.refreshTokenTimeout),
			scopes: OAuthComponents.parseTokenScope(tokenResponse.scope),
			grantExpiresIn: tokenResponse.authorizationExpiresIn
		)

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
			//TODO: get these from a config
			customHeaders: [],
		)
	}

	func tokenEndpointRequest(
		authServerMetadata: AuthServerMetadata,
		grantType: GrantType,
		parameters: [String: String],
		customHeaders: [HTTPField]
	) async throws -> HTTPDataResponse {
		let url = try authServerMetadata.resolve(endpoint: .token)

		var modifiedParams = parameters
		modifiedParams["grant_type"] = grantType.rawValue

		let requestBody = HTTPRequestBody(
			url: url,
			method: .post,
			httpBody: modifiedParams.urlEncodedHTTPBody,
			customHeaders: customHeaders,
			//default accept is "application/json"
			contentType: "application/x-www-form-urlencoded;charset=UTF-8",
		)

		if let dpopSigner {
			return try await dpopSigner.authenticated(
				requestBody: requestBody,
				token: nil,
				fetcher: authFetcher
			)
		} else {
			return try await authFetcher.data(for: requestBody)
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
