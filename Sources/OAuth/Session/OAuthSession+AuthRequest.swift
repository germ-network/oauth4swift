//
//  OAuthSession+AuthRequest.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/25/26.
//

import Foundation
import GermConvenience

extension OAuthSessionCapabilities {
	public func authResponse(
		for request: HTTPRequestBody,
	) async throws -> HTTPDataResponse {
		let sessionState = try session
		let serverMetadata = try await lazyServerMetadata.lazyValue(
			isolation: self
		)

		let _ = try URL(string: serverMetadata.issuer).tryUnwrap.origin

		let result = try await retryNonceRequest(request: request)

		// FIXME: This isn't really to spec: 401 doesn't mean "refresh", it just means unauthorized.
		if result.response.status.kind == .successful {
			return result
		}

		guard case result.response.status.code = 401 else {
			throw OAuthError.httpResponse(response: result)
		}

		//try to refresh the token
		let _ = try await conservingRefresh(state: sessionState)

		return try await retryNonceRequest(request: request)
	}

	func retryNonceRequest(
		request: HTTPRequestBody,
	) async throws -> HTTPDataResponse {
		let response = try await protectedResource(for: request)
		//retry if nonceError
		if response.isDPoPNonceError {
			return try await protectedResource(for: request)
		}
		return response
	}

	//needs to have optional access to a dpopSigner, so it is a method
	//on a OAutSessionCapabilities and not a static method
	func protectedResource(
		for request: HTTPRequestBody,
	) async throws -> HTTPDataResponse {
		let session = try session

		return try await resource(
			for: request,
			accessToken: session.mutable.accessToken.value,
		)
	}

	func resource(
		for requestBody: HTTPRequestBody,
		accessToken: String,
	) async throws -> HTTPDataResponse {
		if let dpopSigner = self as? DPoPSigning {
			var requestBody = requestBody
			requestBody.request.headerFields[.authorization] = "DPoP \(accessToken)"

			return try await dpopSigner.authenticated(
				requestBody: requestBody,
				token: accessToken,
				fetcher: authFetcher
			)
		} else {
			var requestBody = requestBody
			requestBody.request.headerFields[.authorization] = "Bearer \(accessToken)"

			return try await authFetcher.data(for: requestBody)
		}
	}

	//conserving in that it reuses result if a refresh is alread in flght
	private func conservingRefresh(state: SessionState) async throws -> SessionState.Mutable {
		if let refreshTask {
			return try await refreshTask.value
		}

		let newRefreshTask = Task {
			try await refresh(state: state)
		}

		refreshTask = newRefreshTask

		defer {
			refreshTask = nil
		}

		//handle successful refresh
		return try await newRefreshTask.value
	}

	//compare to refreshTokenGrantRequest
	//and processRefreshTokenResponse in oauth4web
	private func refresh(
		state: SessionState,
	) async throws -> SessionState.Mutable {
		let authServerMetadata = try await authServerRequestOptions.authFetcher
			.authServerDiscovery(issuer: try await retriableIssuer)

		let httpResponse = try await authServerRequestOptions.refreshTokenGrantRequest(
			authServerMetadata: authServerMetadata,
			refreshToken: state.mutable.refreshToken.tryUnwrap.value,
		)
		let tokenResponse = try OAuthComponents.processRefreshTokenResponse(
			response: httpResponse)

		//check the token response is valid, e.g., asserting the authorization
		//server can really issue the token for that `sub` parameter in the
		//tokenResponse; also passes the current session state to allow verifying
		//that the token sub hasn't changed during refresh:
		let previousState = ImmutableSessionState(
			client: state.client,
			issuingServer: state.issuingServer,
			additionalParams: state.additionalParams,
			grantScopes: state.grantScopes
		)

		if try await authServerRequestOptions.tokenValidator(
			tokenResponse, authServerMetadata, previousState) == false
		{
			throw OAuthError.tokenInvalid
		}

		let newSessionState = SessionState.Mutable(
			accessToken: .init(
				value: tokenResponse.accessToken, expiresIn: tokenResponse.expiresIn
			),
			refreshToken: .init(
				value: tokenResponse.refreshToken,
				timeout: tokenResponse.refreshTokenTimeout),
			scopes: OAuthComponents.parseTokenScope(tokenResponse.scope),
			grantExpiresIn: tokenResponse.authorizationExpiresIn
		)

		return newSessionState
	}
}

extension HTTPDataResponse {

	///is very different from oauth4web that seems to just parse the header
	var isDPoPNonceError: Bool {
		switch response.status.code {
		case 401:
			//this only works if it is the first challenge in the header error
			if let wwwAuthHeader = response.headerFields[.wwwAuthenticate] {
				if wwwAuthHeader.starts(with: "DPoP") {
					return wwwAuthHeader.contains("error=\"use_dpop_nonce\"")
				}
			}
		// https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid
		case 400:
			do {
				let err = try JSONDecoder().decode(
					OAuthErrorResponse.self, from: data)
				return err.error == "use_dpop_nonce"
			} catch {
				return false
			}
		default:
			return false
		}

		return false
	}
}
