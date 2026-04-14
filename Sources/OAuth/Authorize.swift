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
	let pkceVerifier: PKCEVerifier
	let parameters: FormParameters?
	let issuer: URL
	var stateToken: String?

	public init(
		clientMetadata: OAuthClient,
		clientAuthentication: any OAuthClientAuthenticatable,
		scopes: [String]? = nil,
		stateToken: String?,
		pkceVerifier: PKCEVerifier = .init(),
		parameters: FormParameters?,
		issuer: URL
	) {
		self.clientMetadata = clientMetadata
		self.clientAuthentication = clientAuthentication
		self.stateToken = stateToken
		self.pkceVerifier = pkceVerifier
		self.parameters = parameters
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
		let authServerMetadata = try await authFetcher.authServerDiscovery(
			issuer: authorizeInputs.issuer
		).tryUnwrap

		var authorizeInputs = authorizeInputs

		// If PKCE is not supported, and we don't have a state parameter, generate a
		// state parameter using a UUID:
		if authorizeInputs.stateToken == nil {
			switch authServerMetadata.codeChallengeMethodsSupported?.contains("S256") {
			case nil, false:
				authorizeInputs.stateToken = UUID().uuidString
			default:
				break
			}
		}

		let clientId = authorizeInputs.clientMetadata.clientId
		let challenge = authorizeInputs.pkceVerifier.challenge
		let scopes = authorizeInputs.requestedScopes.joined(separator: " ")
		var parameters = FormParameters([
			"client_id": clientId,
			"scope": scopes,
			"response_type": "code",
			"redirect_uri": authorizeInputs.clientMetadata.redirectURI
				.absoluteString,
			"code_challenge": challenge.value,
			"code_challenge_method": challenge.method,
		])

		// todo: merging with authorizeInputs.parameters
		// if let additionalParameters = authorizeInputs.parameters {
		// 	parameters = parameters.merging(additionalParameters, uniquingKeysWith: { a, b in a }))

		if let state = authorizeInputs.stateToken {
			parameters["state"] = state
		}

		// If we're using PAR, perform the request and replace the parameters for
		// authorization:
		if authServerMetadata.pushedAuthorizationRequestEndpoint != nil {
			let parHTTPResponse = try await pushedAuthorizationRequest(
				authServerMetadata: authServerMetadata,
				clientMetadata: authorizeInputs.clientMetadata,
				clientAuthentication: authorizeInputs.clientAuthentication,
				parameters: parameters
			)

			let parResponse = try OAuthComponents.processPushedAuthorizationResponse(
				response: parHTTPResponse
			)

			parameters = FormParameters([
				"client_id": clientId,
				"request_uri": parResponse.requestURI,
			])
		}

		let authorizationUrl = try Self.authorizationURL(
			authorizationEndpoint: authServerMetadata.authorizationEndpoint,
			parameters: parameters
		)

		let scheme = try authorizeInputs.clientMetadata.redirectURIScheme

		let callbackURL = try await userAuthenticator(authorizationUrl, scheme)

		return try await finishAuthorization(
			callbackURL: callbackURL,
			authInputs: authorizeInputs,
			authServerMetadata: authServerMetadata,
		)
	}

	func pushedAuthorizationRequest(
		authServerMetadata: AuthServerMetadata,
		clientMetadata: OAuthClient,
		clientAuthentication: any OAuthClientAuthenticatable,
		parameters: FormParameters,
		headers: HTTPFields? = nil,
	) async throws -> HTTPDataResponse {
		let parEndpoint = try authServerMetadata.resolve(
			endpoint: .par)

		var rawHeaders = headers ?? HTTPFields()
		rawHeaders[.accept] = HTTPContentType.json.rawValue
		rawHeaders[.contentType] = HTTPContentType.formData.rawValue

		let (params, headers) = try await clientAuthentication.authenticate(
			client: clientMetadata,
			authorizationServer: authServerMetadata,
			parameters: parameters,
			headers: rawHeaders
		)

		let request = try BundledHTTPRequest(
			request: .init(
				method: .post,
				url: parEndpoint,
				headerFields: headers
			),
			body: params.data
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
		authorizationEndpoint: URL,
		parameters: FormParameters
	) throws -> URL {
		var components = URLComponents(
			url: authorizationEndpoint, resolvingAgainstBaseURL: false)

		components?.queryItems = parameters.asQueryItems()

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
		parameters["refresh_token"] = refreshToken

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
			body: parameters.data
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
