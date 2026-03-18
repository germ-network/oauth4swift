//
//  DPoPSigning.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/26/26.
//

import Crypto
import Foundation
import GermConvenience

public protocol DPoPSigning: Actor {
	var dpopKey: DPoPKey { get throws }

	func getNonce(origin: String) -> IndexedNonce?
	func cacheNonce(response: HTTPDataResponse, requestUrl: URL) throws
}

extension DPoPSigning {
	func addProof(
		request: URLRequest,
		token: String?
	) throws -> URLRequest {
		let requestOrigin = try (request.url?.origin)
			.tryUnwrap(DPoPError.requestInvalid(request))

		let nonce = getNonce(origin: requestOrigin)

		//right now the RFC has SHA256 baked into the RFC and a new draft needed
		//to specify alg agility
		let tokenHash = token.map {
			SHA256.hash(data: $0.utf8Data)
				.data.base64URLEncodedString()
		}
		let jwt = try dpopKey.sign(
			payload: .init(
				endpointUrl: (request.url?.targetURI).tryUnwrap,
				httpMethod: request.httpMethod.tryUnwrap(
					OAuthError.missingHTTPMethod),
				nonce: nonce?.nonce,
				accessTokenHash: tokenHash
			)
		)

		var output = request
		output.setValue(jwt.string, forHTTPHeaderField: "DPoP")

		return output
	}

	func nonceRetryAuthenticated(
		request: URLRequest,
		token: String?,
		authFetcher: HTTPFetcher
	) async throws -> HTTPDataResponse {
		let firstResponse = try await authenticated(
			request: request,
			token: token,
			fetcher: authFetcher
		)

		//retry if nonceError
		if firstResponse.isDPoPNonceError {
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
		request: URLRequest,
		token: String?,
		fetcher: HTTPFetcher
	) async throws -> HTTPDataResponse {
		let proofRequest = try addProof(
			request: request,
			token: token,
		)

		let response = try await fetcher.data(for: proofRequest)

		try cacheNonce(
			response: response,
			requestUrl: proofRequest.url.tryUnwrap
		)

		return response
	}
}
