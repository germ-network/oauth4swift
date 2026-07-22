//
//  OAuthSession+AuthRequest.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/25/26.
//

import Foundation
import GermConvenience
import Logging

extension OAuth.SessionCapabilities {
	public func authResponse(
		for request: BundledHTTPRequest,
	) async throws -> HTTPDataResponse {
		let result = try await retryNonceRequest(request: request)

		if result.response.status.kind == .successful {
			return result
		}

		// FIXME: This isn't really to spec: 401 doesn't mean "refresh", it just means unauthorized.
		guard result.response.status.code == 401 else {
			throw OAuth.Errors.httpResponse(response: result)
		}

		//try to refresh the token
		let _ = try await refresh()?.value

		return try await retryNonceRequest(request: request)
	}

	func retryNonceRequest(
		request: BundledHTTPRequest,
	) async throws -> HTTPDataResponse {
		let response = try await resource(
			for: request,
			accessToken: authToken
		)
		//retry if nonceError
		if OAuth.DPoP.Endpoint.resource
			.isDPoPNonceError(bundledResponse: response)
		{
			return try await resource(
				for: request,
				accessToken: authToken
			)
		}
		return response
	}

	func resource(
		for request: BundledHTTPRequest,
		accessToken: OAuth.AccessToken,
	) async throws -> HTTPDataResponse {
		if let dpopSigner = self as? OAuth.DPoP.Signing {
			var request = request
			request.request
				.headerFields[.authorization] = "DPoP " + accessToken.value

			return try await dpopSigner.authenticated(
				request: request,
				token: accessToken,
				fetcher: authFetcher
			)
		} else {
			var request = request
			request.request
				.headerFields[.authorization] = "Bearer " + accessToken.value

			return try await authFetcher.data(for: request)
		}
	}

	//a hook for a client app to manually refresh
	//returns a task to optionally await
	@discardableResult
	public func refresh(
		debounce: TimeInterval? = nil
	) throws -> Task<OAuth.AccessToken, Error>? {
		startRefresh(
			continueCondition: Self.refreshClosure(debounce: debounce),
			refreshClosure: refresh(stateSnapshot:refreshToken:)
		)
	}

	//returns if should refresh
	static private func refreshClosure(
		debounce: TimeInterval?
	) -> (OAuth.RefreshToken?) -> Bool {
		{ refreshToken in
			guard let debounce else {
				return true
			}
			guard let lastRefreshed = refreshToken?.fetchedOn
			else {
				return true
			}
			let lastRefreshInterval = Date().timeIntervalSince(lastRefreshed)

			if lastRefreshInterval < debounce {
				Logger(label: "OAuth.SessionCapabilities")
					.notice(
						"skipping refresh, last fetched \(lastRefreshInterval / (3600 * 24)) days ago, debounce: \(debounce))"
					)
			}

			return lastRefreshInterval > debounce
		}
	}

	//compare to refreshTokenGrantRequest
	//and processRefreshTokenResponse in oauth4web
	private func refresh(
		stateSnapshot: OAuth.SessionState.Snapshot,
		refreshToken: OAuth.RefreshToken
	) async throws -> OAuth.SessionState.TokenState? {
		Logger(label: "OAuthSessionCapabilities")
			.notice("started token refresh")
		let httpResponse = try await refreshTokenGrantRequest(
			authServerMetadata: try await authServerMetadata,
			additionalParameters: tokenRefreshOptions.additionalTokenRequestParameters,
			refreshToken: refreshToken
		)

		//Only invalid_grant confirms that the refresh token is no longer usable.
		let tokenResponse: TokenEndpointResponse
		do {
			tokenResponse = try OAuth.processRefreshTokenResponse(
				response: httpResponse)
		} catch {
			if case OAuth.Errors.oauthError(let errorBody, let status) = error,
				!(errorBody.error == "invalid_grant" && status.code == 400)
			{
				Logger(label: "OAuth.SessionCapabilities")
					.error(
						"refresh error, preserving session \(error)"
					)
				throw error
			}

			Logger(label: "OAuth.SessionCapabilities")
				.error("error refreshing, terminating session \(error)")
			return nil
		}

		do {
			//check the token response is valid, e.g., asserting the authorization
			//server can really issue the token for that `sub` parameter in the
			//tokenResponse; also passes the current session state to allow verifying
			//that the token sub hasn't changed during refresh:

			guard
				try await tokenRefreshOptions
					.validate(
						tokenResponse: tokenResponse,
						authServerMetadata: authServerMetadata,
						previousState: stateSnapshot
					)
			else {
				throw OAuth.Errors.tokenInvalid
			}
		} catch {
			Logger(label: "OAuth.SessionCapabilities")
				.error("error refreshing, terminating session \(error)")
			return nil
		}

		let newTokenState = OAuth.SessionState.TokenState(
			accessToken: .init(
				value: tokenResponse.accessToken,
				expiresIn: .init(tokenResponse.expiresIn)
			),
			refreshToken: .init(
				value: tokenResponse.refreshToken,
				timeout: .init(tokenResponse.refreshTokenTimeout)
			),
			scopes: OAuth.parseTokenScope(
				tokenResponse.scope, parent: stateSnapshot.grantScopes),
			grantExpiresIn: .init(tokenResponse.authorizationExpiresIn)
		)

		Logger(label: "OAuthSessionCapabilities")
			.notice("succeeded token refresh")
		return newTokenState
	}
}
