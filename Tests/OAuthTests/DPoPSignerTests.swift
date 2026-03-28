//
//  DPoPSignerTests.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/11/26.
//

import Crypto
import Foundation
import GermConvenience
import Testing

@testable import OAuth

struct Test {
	let dpopSigner = AuthDPopState(
		dpopKey: .generateP256(),
		decoder: { (dataResponse, requestUrl) in
			let nonce = dataResponse.response
				.headerFields[try .dpopNonce.tryUnwrap]
			guard let nonce else {
				return nil
			}

			//henceforth should throw instead of return nil as nonce is expected
			return try IndexedNonce(
				requestUrl: requestUrl,
				nonce: nonce
			)
		}
	)

	@Test(
		"add DpopProof",
		arguments: [UUID().uuidString, nil],
		[UUID().uuidString, nil]
	)
	func testAddProof(token: String?, nonce: String?) async throws {
		let url = try #require(URL(string: "https://example.com/endpoint"))

		if let nonce {
			await dpopSigner.cache(
				nonce: .init(
					origin: try url.origin,
					nonce: nonce
				)
			)
		}

		let signedRequest = try await dpopSigner.addProof(
			request: .init(request: .init(url: url)),
			token: token
		)

		let dpopHeader = try signedRequest.request
			.headerFields[try .dpop.tryUnwrap]
			.tryUnwrap

		let jwt = try JWT(string: dpopHeader)

		let header = try JSONDecoder().decode(
			JWT.Header.self,
			from: try #require(Data(base64URLEncoded: jwt.header))
		)

		#expect(header.typ == "dpop+jwt")
		#expect(header.alg == "ES256")

		#expect(try header.jwk.verifyP256(jwt: jwt) == true)
	}

	//    @Test func singleDpopRequest() async throws {
	//		let request = URLRequest(
	//			url: try #require(URL(string: "example.com/endpoint"))
	//		)
	//
	//		let mockFetcher = MockFetcher { request in
	//
	//		}
	//
	//		let response = try await dpopSigner.authenticated(
	//			request: request,
	//			token: nil,
	//			fetcher: mockFetcher
	//		)
	//    }
}

extension AuthDPopState {
	func cache(nonce: IndexedNonce) {
		nonceCache.setObject(nonce, forKey: nonce.origin as NSString)
	}
}

extension JWT {
	init(string: String) throws {
		let components = string.split(separator: JWT.period)
		#expect(components.count == 3)
		self.init(
			header: .init(components[0]),
			payload: .init(components[1]),
			signature: .init(components[2])
		)
	}
}

extension JWT.JWK {

	func verifyP256(jwt: JWT) throws -> Bool {
		let signOver = (jwt.header + [JWT.period] + jwt.payload).utf8Data
		let signatureData = try #require(Data(base64URLEncoded: jwt.signature))

		return try p256Key.isValidSignature(
			.init(rawRepresentation: signatureData),
			for: SHA256.hash(data: signOver)
		)
	}

	var p256Key: P256.Signing.PublicKey {
		get throws {
			#expect(kty == "EC")
			#expect(crv == "P-256")
			let xComponent = try #require(Data(base64URLEncoded: x))
			let yComponent = try #require(Data(base64URLEncoded: y))

			// Public key consists of 04 | X | Y where X and Y are the same length
			// (Which, for P256, is 256 / 8 = 32 bytes each.)
			// https://developer.apple.com/forums/thread/680554
			let x963 = [UInt8(4)] + xComponent + yComponent

			return try P256.Signing.PublicKey(x963Representation: x963)
		}
	}
}

struct MockFetcher {
	let host: String = "example.com"

	let resolver: @Sendable (BundledHTTPRequest) throws -> HTTPDataResponse
}

extension MockFetcher: HTTPFetcher {
	func data(
		for request: BundledHTTPRequest
	) async throws -> GermConvenience.HTTPDataResponse {
		let url = try #require(request.request.url)
		assert(url.scheme == "https")
		assert(url.host() == host)

		return try resolver(request)
	}
}
