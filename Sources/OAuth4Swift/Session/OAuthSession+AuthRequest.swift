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
		let sessionState = try session
		let serverMetadata = try await lazyServerMetadata.lazyValue(
			isolation: self
		)

		let _ = try URL(string: serverMetadata.issuer).tryUnwrap.origin

		let result = try await retryNonceRequest(request: request)

		if result.response.status.kind == .successful {
			return result
		}

		// FIXME: This isn't really to spec: 401 doesn't mean "refresh", it just means unauthorized.
		guard case result.response.status.code = 401 else {
			throw OAuth.Errors.httpResponse(response: result)
		}

		//try to refresh the token
		let _ = try await conservingRefresh(state: sessionState)

		return try await retryNonceRequest(request: request)
	}

	func retryNonceRequest(
		request: BundledHTTPRequest,
	) async throws -> HTTPDataResponse {
		let response = try await protectedResource(for: request)
		//retry if nonceError
		if OAuth.DPoP.Endpoint.resource
			.isDPoPNonceError(bundledResponse: response)
		{
			return try await protectedResource(for: request)
		}
		return response
	}

	//needs to have optional access to a dpopSigner, so it is a method
	//on a OAutSessionCapabilities and not a static method
	func protectedResource(
		for request: BundledHTTPRequest,
	) async throws -> HTTPDataResponse {
		let session = try session

		return try await resource(
			for: request,
			accessToken: session.tokenState.accessToken.value,
		)
	}

	func resource(
		for request: BundledHTTPRequest,
		accessToken: String,
	) async throws -> HTTPDataResponse {
		if let dpopSigner = self as? OAuth.DPoP.Signing {
			var request = request
			request.request.headerFields[.authorization] = "DPoP \(accessToken)"

			return try await dpopSigner.authenticated(
				request: request,
				token: accessToken,
				fetcher: authFetcher
			)
		} else {
			var request = request
			request.request.headerFields[.authorization] = "Bearer \(accessToken)"

			return try await authFetcher.data(for: request)
		}
	}

	//a hook for a client app to manually refresh
	//doesn't duplicatively return as result as the feedback should come
	//through the refreshed(: hook
	public func refresh() async throws {
		let _ = try await conservingRefresh(state: session)
	}

	//conserving in that it reuses result if a refresh is alread in flght
	private func conservingRefresh(state: OAuth.SessionState) async throws
		-> OAuth.SessionState.TokenState
	{
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
		state: OAuth.SessionState,
	) async throws -> OAuth.SessionState.TokenState {
		let authServerMetadata =
			try await lazyServerMetadata
			.lazyValue(isolation: self)

		let previousState = OAuth.SessionState.Snapshot(
			issuingServer: state.issuingServer,
			additionalParams: state.additionalParams,
			grantScopes: state.grantScopes
		)

		let httpResponse = try await refreshTokenGrantRequest(
			authServerMetadata: authServerMetadata,
			additionalParameters: authServerRequestOptions.additionalParameters,
			refreshToken: state.tokenState.refreshToken.tryUnwrap.value
		)

		//if we get an HTTP response but it isn't successful we nil the session
		let tokenResponse: TokenEndpointResponse
		do {
			tokenResponse = try OAuth.processRefreshTokenResponse(
				response: httpResponse)

			//check the token response is valid, e.g., asserting the authorization
			//server can really issue the token for that `sub` parameter in the
			//tokenResponse; also passes the current session state to allow verifying
			//that the token sub hasn't changed during refresh:

			guard try await authServerRequestOptions.tokenValidator(
				tokenResponse, authServerMetadata, previousState) else {
				throw OAuth.Errors.tokenInvalid
			}
		} catch {
			try refreshed(tokenState: nil)
			Logger(label: "refresh")
				.error("error refreshing, terminating session \(error)")
			throw error
		}

		let newTokenState = OAuth.SessionState.TokenState(
			accessToken: .init(
				value: tokenResponse.accessToken,
				expiresIn: tokenResponse.expiresIn
			),
			refreshToken: .init(
				value: tokenResponse.refreshToken,
				timeout: tokenResponse.refreshTokenTimeout),
			scopes: OAuth.parseTokenScope(
				tokenResponse.scope, parent: previousState.grantScopes),
			grantExpiresIn: tokenResponse.authorizationExpiresIn
		)

		try refreshed(tokenState: newTokenState)

		return newTokenState
	}
}
