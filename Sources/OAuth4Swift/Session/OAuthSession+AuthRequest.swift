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
			return try await dpopSigner.authenticated(
				request: request.settingHeader(
					"DPoP " + accessToken.value, for: .authorization),
				token: accessToken,
				fetcher: authFetcher
			)
		} else {
			return try await authFetcher.data(
				for: request.settingHeader(
					"Bearer " + accessToken.value, for: .authorization)
			)
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
		let metadata = try await authServerMetadata
		// A server that does not offer refresh_token gets no request, but the
		// session stays alive until its access token expires: throwing preserves
		// the previous state, where returning nil would terminate the session.
		//
		// RFC 8414 2's default for an omitted grant_types_supported is
		// ["authorization_code", "implicit"] - strictly, absent means no refresh.
		// We deliberately read absent as "unstated" and attempt the refresh:
		// many servers omit the field yet support refresh, and one that truly
		// does not will answer unsupported_grant_type, which also preserves
		// the session.
		guard
			metadata.grantTypesSupported?.contains(
				OAuth.GrantType.refreshToken.rawValue) != false
		else {
			throw OAuth.Errors.refreshNotSupported
		}

		Logger(label: "OAuthSessionCapabilities")
			.notice("started token refresh")
		let httpResponse = try await refreshTokenGrantRequest(
			authServerMetadata: metadata,
			additionalParameters: tokenRefreshOptions.additionalTokenRequestParameters,
			refreshToken: refreshToken
		)

		//Only invalid_grant confirms that the refresh token is no longer usable.
		//Everything else preserves the session so the caller can retry.
		let tokenResponse: TokenEndpointResponse
		do {
			tokenResponse = try OAuth.processRefreshTokenResponse(
				response: httpResponse)
		} catch OAuth.Errors.oauthError(let errorBody, let status)
			where errorBody.error == "invalid_grant" && status.code == 400
		{
			Logger(label: "OAuth.SessionCapabilities")
				.error("invalid_grant, terminating session \(errorBody)")
			return nil
		} catch {
			Logger(label: "OAuth.SessionCapabilities")
				.warning("refresh error, preserving session \(error)")
			throw error
		}

		//check the token response is valid, e.g., asserting the authorization
		//server can really issue the token for that `sub` parameter in the
		//tokenResponse; also passes the current session state to allow verifying
		//that the token sub hasn't changed during refresh:

		//per TokenRefreshOptions, false means the response is invalid, while a
		//thrown error means validity couldn't be resolved - e.g. an offline
		//client - and so preserves the session
		guard
			try await tokenRefreshOptions
				.validate(
					tokenResponse: tokenResponse,
					authServerMetadata: metadata,
					previousState: stateSnapshot
				)
		else {
			Logger(label: "OAuth.SessionCapabilities")
				.error("token failed validation, terminating session")
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
