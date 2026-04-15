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
	let clientId: String
	let scopes: [String]
	let redirectURI: URL
	let clientAuthentication: any OAuth.ClientAuthenticatable
	let pkceVerifier: PKCEVerifier
	let parameters: FormParameters?
	let issuer: URL
	var stateToken: String?

	public init(
		clientId: String,
		redirectURI: URL,
		clientAuthentication: any OAuth.ClientAuthenticatable,
		scopes: [String],
		stateToken: String?,
		pkceVerifier: PKCEVerifier = .init(),
		parameters: FormParameters?,
		issuer: URL
	) {
		self.clientId = clientId
		self.redirectURI = redirectURI
		self.clientAuthentication = clientAuthentication
		self.scopes = scopes
		self.stateToken = stateToken
		self.pkceVerifier = pkceVerifier
		self.parameters = parameters
		self.issuer = issuer
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

		let challenge = authorizeInputs.pkceVerifier.challenge
		let scopes = authorizeInputs.scopes.joined(separator: " ")
		var parameters = FormParameters([
			"client_id": authorizeInputs.clientId,
			"scope": scopes,
			"response_type": "code",
			"redirect_uri": authorizeInputs.redirectURI
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
				clientId: authorizeInputs.clientId,
				authServerMetadata: authServerMetadata,
				clientAuthentication: authorizeInputs.clientAuthentication,
				parameters: parameters
			)

			let parResponse = try OAuth.processPushedAuthorizationResponse(
				response: parHTTPResponse
			)

			parameters = FormParameters([
				"client_id": authorizeInputs.clientId,
				"request_uri": parResponse.requestURI,
			])
		}

		let authorizationUrl = try Self.authorizationURL(
			authorizationEndpoint: authServerMetadata.authorizationEndpoint,
			parameters: parameters
		)

		let scheme = try authorizeInputs.redirectURI.scheme
			.tryUnwrap(OAuth.Errors.missingScheme)

		let callbackURL = try await userAuthenticator(authorizationUrl, scheme)

		return try await finishAuthorization(
			callbackURL: callbackURL,
			authInputs: authorizeInputs,
			authServerMetadata: authServerMetadata,
		)
	}

	func pushedAuthorizationRequest(
		clientId: String,
		authServerMetadata: AuthServerMetadata,
		clientAuthentication: any OAuth.ClientAuthenticatable,
		parameters: FormParameters,
		headers: HTTPFields? = nil,
	) async throws -> HTTPDataResponse {
		let parEndpoint = try authServerMetadata.resolve(
			endpoint: .par)

		var rawHeaders = headers ?? HTTPFields()
		rawHeaders[.accept] = HTTPContentType.json.rawValue
		rawHeaders[.contentType] = HTTPContentType.formData.rawValue

		let (params, headers) = try await clientAuthentication.authenticate(
			inputs: .init(
				clientId: clientId,
				authServerMetadata: authServerMetadata,
				parameters: parameters,
				headers: rawHeaders
			)
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
		let callbackParameters = try OAuth.validateAuthResponse(
			authServerMetadata: authServerMetadata,
			callbackURL: callbackURL,
			expectedState: authInputs.stateToken
		)

		let httpResponse = try await authorizationCodeGrantRequest(
			clientId: authInputs.clientId,
			authServerMetadata: authServerMetadata,
			clientAuthentication: authInputs.clientAuthentication,
			callbackParameters: callbackParameters,
			redirectURI: authInputs.redirectURI,
			pkceVerifier: authInputs.pkceVerifier.verifier,
			additionalParameters: additionalParameters,
		)

		let (mutableSessionState, additionalParams) =
			try await processAuthorizationCodeOAuth2Response(
				authServerMetadata: authServerMetadata,
				scopes: authInputs.scopes,
				response: httpResponse
			)

		return .init(
			clientId: authInputs.clientId,
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
		clientId: String,
		authServerMetadata: AuthServerMetadata,
		clientAuthentication: any OAuth.ClientAuthenticatable,
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
			clientId: clientId,
			authServerMetadata: authServerMetadata,
			clientAuthentication: clientAuthentication,
			grantType: .authorizationCode,
			parameters: parameters,
		)
	}

	func processAuthorizationCodeOAuth2Response(
		authServerMetadata: AuthServerMetadata,
		scopes: [String],
		response: HTTPDataResponse
	) async throws -> (SessionState.Mutable, [String: String]?) {
		let tokenResponse = try OAuth.processGenericAccessToken(
			response: response)

		//check the token response is valid, e.g., asserting the authorization
		//server can really issue the token for that `sub` parameter in the
		//tokenResponse
		if try await tokenValidator(tokenResponse, authServerMetadata, nil) == false {
			throw OAuth.Errors.tokenInvalid
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
			scopes: OAuth.parseTokenScope(
				tokenResponse.scope,
				parent: scopes
			),
			grantExpiresIn: tokenResponse.authorizationExpiresIn
		)

		return (sessionState, additionalParams)
	}

	func refreshTokenGrantRequest(
		clientId: String,
		authServerMetadata: AuthServerMetadata,
		clientAuthentication: any OAuth.ClientAuthenticatable,
		refreshToken: String,
	) async throws -> HTTPDataResponse {
		var parameters = FormParameters(additionalParameters)
		parameters["refresh_token"] = refreshToken

		return try await tokenEndpointRequest(
			clientId: clientId,
			authServerMetadata: authServerMetadata,
			clientAuthentication: clientAuthentication,
			grantType: .refreshToken,
			parameters: parameters,
		)
	}

	func tokenEndpointRequest(
		clientId: String,
		authServerMetadata: AuthServerMetadata,
		clientAuthentication: any OAuth.ClientAuthenticatable,
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
			inputs: .init(
				clientId: clientId,
				authServerMetadata: authServerMetadata,
				parameters: parametersWithGrantType,
				headers: rawHeaders
			)
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
