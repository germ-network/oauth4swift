//
//  Authorizer.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 4/16/26.
//

import Foundation
import GermConvenience
import HTTPTypes
import Logging

extension OAuth {
	public protocol Authorizer {
		var authorizeInputs: AuthorizeInputs { get }
		var tokenRequestOptions: TokenRequestOptions { get }
		var authFetcher: HTTPFetcher { get }
	}
}

extension OAuth {
	public struct AuthorizeInputs: Sendable {
		public let clientInfo: ClientInfo
		let pkceVerifier: PKCEVerifier
		let authServerMetadata: AuthServerMetadata
		//the client should resolve authEndpoint from authServerMetadata
		let authEndpoint: URL
		let inputToken: String?
		let additionalParameters: FormParameters?
		//Client fetched the AuthServerMetadata to resolve authEndpoint,
		//so it should be able to
		let userAuthenticator: UserAuthenticator
		let clientAuthenticator: any ClientAuth.Authenticable

		public init(
			clientInfo: ClientInfo,
			pkceVerifier: PKCEVerifier = .init(),
			authServerMetadata: AuthServerMetadata,
			authEndpoint: URL,
			inputToken: String?,
			additionalParameters: FormParameters?,
			userAuthenticator: @escaping UserAuthenticator,
			clientAuthenticator: some ClientAuth.Authenticable
		) {
			self.clientInfo = clientInfo
			self.pkceVerifier = pkceVerifier
			self.authServerMetadata = authServerMetadata
			self.authEndpoint = authEndpoint
			self.inputToken = inputToken
			self.additionalParameters = additionalParameters
			self.userAuthenticator = userAuthenticator
			self.clientAuthenticator = clientAuthenticator
		}
	}
}

extension OAuth.Authorizer {
	public func performUserAuthentication() async throws -> OAuth.SessionState.Archive {

		// If PKCE is not supported, and we don't have a state parameter, generate a
		// state parameter using a UUID:
		let stateToken: String? = {
			if let inputToken = authorizeInputs.inputToken {
				return inputToken
			}

			switch authorizeInputs.authServerMetadata.codeChallengeMethodsSupported?
				.contains("S256")
			{
			case nil, false:
				return UUID().uuidString
			default:
				return nil
			}
		}()

		let challenge = authorizeInputs.pkceVerifier.challenge
		let scopes = authorizeInputs.clientInfo.scopes.joined(separator: " ")

		//any parameters we set in OAuth override conflicting parameters
		//from the client app
		var parameters = authorizeInputs.additionalParameters ?? .init()

		parameters.mergeReplacingValues(
			with: .init(
				[
					"scope": scopes,
					"response_type": "code",
					"redirect_uri": authorizeInputs.clientInfo.redirectURI
						.absoluteString,
					"code_challenge": challenge.value,
					"code_challenge_method": challenge.method,
				]
			))

		if let stateToken {
			parameters["state"] = [stateToken]
		}

		// If we're using PAR, perform the request and replace the parameters for
		// authorization:
		if authorizeInputs.authServerMetadata.pushedAuthorizationRequestEndpoint != nil {
			let parHTTPResponse = try await pushedAuthorizationRequest(
				authServerMetadata: authorizeInputs.authServerMetadata,
				parameters: parameters,
				clientAuthenticator: authorizeInputs.clientAuthenticator
			)

			let parResponse = try OAuth.processPushedAuthorizationResponse(
				response: parHTTPResponse
			)

			//reset the parameters
			parameters = FormParameters([
				"client_id": authorizeInputs.clientInfo.clientId,
				"request_uri": parResponse.requestURI,
			])
		}

		let authorizationUrl = try Self.authorizationURL(
			authorizationEndpoint: authorizeInputs.authServerMetadata
				.authorizationEndpoint,
			parameters: parameters
		)

		let scheme = try authorizeInputs.clientInfo.redirectURI.scheme
			.tryUnwrap(OAuth.Errors.missingScheme)

		let callbackURL = try await authorizeInputs.userAuthenticator(
			authorizationUrl,
			scheme
		)

		return try await finishAuthorization(
			callbackURL: callbackURL,
			expectedState: stateToken,
			authServerMetadata: authorizeInputs.authServerMetadata,
			clientAuthenticator: authorizeInputs.clientAuthenticator
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
		clientAuthenticator: any OAuth.ClientAuth.Authenticable
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
		clientAuthenticator: any OAuth.ClientAuth.Authenticable
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
			additionalParameters: tokenRequestOptions.additionalParameters,
		)

		let (tokenState, additionalParams) =
			try await processAuthorizationCodeOAuth2Response(
				authServerMetadata: authServerMetadata,
				scopes: authorizeInputs.clientInfo.scopes,
				response: httpResponse,
				tokenValidator: tokenRequestOptions.tokenValidator
			)

		return .init(
			clientId: authorizeInputs.clientInfo.clientId,
			clientAuthMethod: clientAuthenticator.tokenEndpointAuthMethod,
			dPopKey: try (clientAuthenticator as? DPoPSigning)?.dpopKey,
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
		tokenValidator: OAuth.TokenRequestOptions.TokenValidator
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
