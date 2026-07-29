//
//  DPoPSigning.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/26/26.
//

import Base64
import Crypto
import Foundation
import GermConvenience

extension OAuth.DPoP {
	public protocol Signing: Actor {
		var dpopKey: Key { get }

		func getNonce(origin: String) -> IndexedNonce?
		func cacheNonce(response: HTTPDataResponse, requestUrl: URL) throws
	}
}

extension OAuth.DPoP.Signing {
	func addProof(
		request: BundledHTTPRequest,
		token: OAuth.AccessToken?
	) throws -> BundledHTTPRequest {
		let requestOrigin = try (request.request.url?.origin)
			.tryUnwrap(OAuth.DPoP.Errors.requestInvalid(request.request))

		let nonce = getNonce(origin: requestOrigin)

		//right now the RFC has SHA256 baked into the RFC and a new draft needed
		//to specify alg agility
		let tokenHash = token.map {
			SHA256.hash(data: $0.value.utf8Data)
				.data.base64URLEncoded(padded: false)
		}
		let jwt = try dpopKey.sign(
			payload: .init(
				endpointUrl: (request.request.url?.targetURI).tryUnwrap,
				httpMethod: request.request.method.rawValue,
				nonce: nonce?.nonce,
				accessTokenHash: tokenHash
			)
		)

		return request.settingHeader(jwt.string, for: try .dpop.tryUnwrap)
	}

	func nonceRetryAuthenticated(
		request: BundledHTTPRequest,
		token: OAuth.AccessToken?,
		authFetcher: HTTPFetcher,
		endpointType: OAuth.DPoP.Endpoint
	) async throws -> HTTPDataResponse {
		let firstResponse = try await authenticated(
			request: request,
			token: token,
			fetcher: authFetcher
		)

		//retry if nonceError
		if endpointType.isDPoPNonceError(bundledResponse: firstResponse) {
			return try await authenticated(
				request: request,
				token: token,
				fetcher: authFetcher
			)
		} else {
			return firstResponse
		}
	}

	//tries just once
	func authenticated(
		request: BundledHTTPRequest,
		token: OAuth.AccessToken?,
		fetcher: HTTPFetcher,
	) async throws -> HTTPDataResponse {
		let proofRequest = try addProof(
			request: request,
			token: token,
		)

		let response = try await fetcher.data(for: proofRequest)

		try cacheNonce(
			response: response,
			requestUrl: proofRequest.request.url.tryUnwrap
		)

		return response
	}
}
