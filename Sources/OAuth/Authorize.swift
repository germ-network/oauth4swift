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
	let clientAuthentication: any OAuthClientAuthenticatable
	let requestedScopes: [String]
	let stateToken: String
	let pkceVerifier: PKCEVerifier
	let parConfig: PARConfiguration?
	let issuer: URL

	public init(
		clientMetadata: OAuthClient,
		clientAuthentication: any OAuthClientAuthenticatable,
		scopes: [String]? = nil,
		stateToken: String = UUID().uuidString,
		pkceVerifier: PKCEVerifier = .init(),
		parConfig: PARConfiguration?,
		issuer: URL
	) {
		self.clientMetadata = clientMetadata
		self.clientAuthentication = clientAuthentication
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
				clientAuthentication: authorizeInputs.clientAuthentication,
				parameters: parParams,
				//TODO: get these from a config
				headers: [],
			)

			let parResponse = try OAuthComponents.processPushedAuthorizationResponse(
				response: parHTTPResponse
			)

			let tokenURL = try Self.authorizationURL(
				authEndpoint: authServerMetadata.authorizationEndpoint,
				clientId: clientId,
				parRequestURI: parResponse.requestURI,
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
		clientAuthentication: any OAuthClientAuthenticatable,
		parameters: [String: String],
		headers: [HTTPField],
	) async throws -> HTTPDataResponse {
		let parEndpoint = try authServerMetadata.resolve(
			endpoint: .par)

		var rawHeaders = HTTPFields(headers)
		rawHeaders[.accept] = HTTPContentType.json.rawValue
		rawHeaders[.contentType] = HTTPContentType.formData.rawValue

		let (params, headers) = try await clientAuthentication.authenticate(
			client: clientMetadata,
			authorizationServer: authServerMetadata,
			parameters: FormParameters(parameters),
			headers: rawHeaders
		)

		let request = try BundledHTTPRequest(
			request: .init(
				method: .post,
				url: parEndpoint,
				headerFields: headers
			),
			parameters: params
		)

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
		clientId: String,
		parRequestURI: String,
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
			client: authInputs.clientMetadata,
			clientAuthentication: authInputs.clientAuthentication,
			callbackParameters: callbackParameters,
			redirectURI: authInputs.clientMetadata.redirectURI,
			pkceVerifier: authInputs.pkceVerifier.verifier,
			additionalParameters: additionalParameters,
		)

		let (mutableSessionState, additionalParams) =
			try await processAuthorizationCodeOAuth2Response(
				authServerMetadata: authServerMetadata,
				client: authInputs.clientMetadata,
				response: httpResponse
			)

		return .init(
			client: authInputs.clientMetadata,
			clientAuthentication: authInputs.clientAuthentication,
			dPopKey: try await dpopSigner?.dpopKey,
			issuingServer: authServerMetadata.issuer,
			additionalParams: additionalParams,
			// We save the first authorization response's scopes as the Authorization
			// Grant's scopes, in future token refresh calls, we can change scopes up
			// and down within the bounds of grantScopes.
			grantScopes: mutableSessionState.scopes,
			mutable: mutableSessionState
		)
	}

	public func authorizationCodeGrantRequest(
		authServerMetadata: AuthServerMetadata,
		client: OAuthClient,
		clientAuthentication: any OAuthClientAuthenticatable,
		callbackParameters: OAuthComponents.AuthResponseParameters,
		redirectURI: URL,
		pkceVerifier: String?,
		additionalParameters: [String: String],
	) async throws -> HTTPDataResponse {
		guard let code = callbackParameters["code"].first else {
			throw OAuthError.missingAuthCode
		}

		var parameters = FormParameters(additionalParameters)
		parameters["redirect_uri"] = redirectURI.absoluteString
		parameters["code"] = code

		if let pkceVerifier {
			parameters["code_verifier"] = pkceVerifier
		}

		return try await tokenEndpointRequest(
			authServerMetadata: authServerMetadata,
			client: client,
			clientAuthentication: clientAuthentication,
			grantType: .authorizationCode,
			parameters: parameters,
		)
	}

	func processAuthorizationCodeOAuth2Response(
		authServerMetadata: AuthServerMetadata,
		client: OAuthClient,
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
			scopes: OAuthComponents.parseTokenScope(
				tokenResponse.scope, parent: client.scopes),
			grantExpiresIn: tokenResponse.authorizationExpiresIn
		)

		return (sessionState, additionalParams)
	}

	func refreshTokenGrantRequest(
		authServerMetadata: AuthServerMetadata,
		client: OAuthClient,
		clientAuthentication: any OAuthClientAuthenticatable,
		refreshToken: String,
	) async throws -> HTTPDataResponse {
		var parameters = FormParameters(additionalParameters)
		parameters.set(name: "refresh_token", value: refreshToken)

		return try await tokenEndpointRequest(
			authServerMetadata: authServerMetadata,
			client: client,
			clientAuthentication: clientAuthentication,
			grantType: .refreshToken,
			parameters: parameters,
		)
	}

	func tokenEndpointRequest(
		authServerMetadata: AuthServerMetadata,
		client: OAuthClient,
		clientAuthentication: any OAuthClientAuthenticatable,
		grantType: GrantType,
		parameters: FormParameters,
	) async throws -> HTTPDataResponse {
		let url = try authServerMetadata.resolve(endpoint: .token)

		var parametersWithGrantType = parameters
		parametersWithGrantType["grant_type"] = grantType.rawValue

		let rawHeaders = HTTPFields(
			dictionaryLiteral: (.accept, HTTPContentType.json.rawValue),
			(.contentType, HTTPContentType.formData.rawValue),
		)

		let (parameters, headers) = try await clientAuthentication.authenticate(
			client: client,
			authorizationServer: authServerMetadata,
			parameters: parametersWithGrantType,
			headers: rawHeaders
		)

		let request = try BundledHTTPRequest(
			request: .init(
				method: .post,
				url: url,
				headerFields: headers
			),
			parameters: parameters
		)

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
