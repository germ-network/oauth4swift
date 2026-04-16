//
//  PerformUserAuthenticate.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 4/15/26.
//

import Foundation
import GermConvenience
import HTTPTypes
import Logging

extension OAuth.Authorizer {
	public func performUserAuthentication() async throws -> OAuth.SessionState.Archive {
		let authServerMetadata = try await authFetcher.authServerDiscovery(
			issuer: authorizeInputs.issuer
		).tryUnwrap

		let clientAuthenticator = try negotiate(
			authServerMetadata: authServerMetadata
		)

		// If PKCE is not supported, and we don't have a state parameter, generate a
		// state parameter using a UUID:
		let stateToken: String? = {
			if let inputToken = authorizeInputs.inputToken {
				return inputToken
			}

			switch authServerMetadata.codeChallengeMethodsSupported?.contains("S256") {
			case nil, false:
				return UUID().uuidString
			default:
				return nil
			}
		}()

		let challenge = authorizeInputs.pkceVerifier.challenge
		
		var parameters = FormParameters([
			"scope": authorizeInputs.clientInfo.scopes,
			"response_type": ["code"],
			"redirect_uri": [authorizeInputs.clientInfo.redirectURI
				.absoluteString],
			"code_challenge": [challenge.value],
			"code_challenge_method": [challenge.method],
		])

		// todo: merging with authorizeInputs.parameters
		// if let additionalParameters = authorizeInputs.parameters {
		// 	parameters = parameters.merging(additionalParameters, uniquingKeysWith: { a, b in a }))

		if let stateToken {
			parameters["state"] = stateToken
		}

		// If we're using PAR, perform the request and replace the parameters for
		// authorization:
		if authServerMetadata.pushedAuthorizationRequestEndpoint != nil {
			let parHTTPResponse = try await pushedAuthorizationRequest(
				authServerMetadata: authServerMetadata,
				parameters: parameters,
				clientAuthenticator: clientAuthenticator
			)

			let parResponse = try OAuth.processPushedAuthorizationResponse(
				response: parHTTPResponse
			)

			parameters = FormParameters([
				"client_id":authorizeInputs.clientInfo.clientId,
				"request_uri": parResponse.requestURI,
			])
		}

		let authorizationUrl = try Self.authorizationURL(
			authorizationEndpoint: authServerMetadata.authorizationEndpoint,
			parameters: parameters
		)

		let scheme = try authorizeInputs.clientInfo.redirectURI.scheme
			.tryUnwrap(OAuth.Errors.missingScheme)

		let callbackURL = try await userAuthenticator(authorizationUrl, scheme)

		return try await finishAuthorization(
			callbackURL: callbackURL,
			expectedState: stateToken,
			authServerMetadata: authServerMetadata,
			clientAuthenticator: clientAuthenticator
		)
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

	func pushedAuthorizationRequest(
		authServerMetadata: AuthServerMetadata,
		parameters: FormParameters,
		headers: HTTPFields? = nil,
		clientAuthenticator: any OAuth.ClientAuthenticatable
	) async throws -> HTTPDataResponse {
		let parEndpoint = try authServerMetadata.resolve(
			endpoint: .par)
		
		var rawHeaders = headers ?? HTTPFields()
		rawHeaders[.accept] = HTTPContentType.json.rawValue
		rawHeaders[.contentType] = HTTPContentType.formUrlEncoded.rawValue

		return try await clientAuthenticator.authenticatedRequest(
			url: parEndpoint,
			method: .post,
			inputs: .init(
				authServerMetadata: authServerMetadata,
				parameters: parameters,
				headers: rawHeaders
			),
			retry: true
		)
	}

	func finishAuthorization(
		callbackURL: URL,
		expectedState: String?,
		authServerMetadata: AuthServerMetadata,
		clientAuthenticator: any OAuth.ClientAuthenticatable
	) async throws -> OAuth.SessionState.Archive {
		let callbackParameters = try OAuth.validateAuthResponse(
			authServerMetadata: authServerMetadata,
			callbackURL: callbackURL,
			expectedState: expectedState
		)

		let httpResponse = try await clientAuthenticator.authorizationCodeGrantRequest(
			authServerMetadata: authServerMetadata,
			callbackParameters: callbackParameters,
			redirectURI: authorizeInputs.clientInfo.redirectURI,
			pkceVerifier: authorizeInputs.pkceVerifier.verifier,
			additionalParameters: authServerRequestOptions.additionalParameters,
		)

		let (tokenState, additionalParams) =
			try await processAuthorizationCodeOAuth2Response(
				authServerMetadata: authServerMetadata,
				scopes: authorizeInputs.clientInfo.scopes,
				response: httpResponse,
				tokenValidator: authServerRequestOptions.tokenValidator
			)

		return .init(
			clientId: authorizeInputs.clientInfo.clientId,
			clientAuthMethod: clientAuthenticator.tokenEndpointAuthMethod,
			dPopKey: try (self as? DPoPSigning)?.dpopKey,
			issuingServer: authServerMetadata.issuer,
			additionalParams: additionalParams,
			// We save the first authorization response's scopes as the Authorization
			// Grant's scopes, in future token refresh calls, we can change scopes up
			// and down within the bounds of grantScopes.
			grantScopes: tokenState.scopes,
			clientAuth: await clientAuthenticator.clientAuthArchive,
			tokenState: tokenState
		)
	}

	func processAuthorizationCodeOAuth2Response(
		authServerMetadata: AuthServerMetadata,
		scopes: [String],
		response: HTTPDataResponse,
		tokenValidator: OAuth.AuthServerRequestOptions.TokenValidator
	) async throws -> (OAuth.SessionState.TokenState, [String: String]?) {
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

		let sessionState = OAuth.SessionState.TokenState(
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
}
