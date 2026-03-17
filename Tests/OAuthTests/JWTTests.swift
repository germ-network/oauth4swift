//
//  JWTTests.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/1/26.
//

import Crypto
import Foundation
import GermConvenience
import Testing

@testable import OAuth

struct TestJWTSigning {
	let key = DPoPKey.generateP256()

	@Test func testSigning() async throws {
		let payload = UUID().uuidString

		let privateKey = try P256.Signing.PrivateKey(rawRepresentation: key.keyData)
		let signer = ECDSASigner(key: privateKey)
		let jwt =
			try signer
			.sign(
				keyType: "dpop+jwt",
				payload: payload
			)

		let verifier = ECDSASigner(key: privateKey)
		#expect(
			try verifier.verify(
				Data(base64URLEncoded: jwt.signature).tryUnwrap,
				signs: jwt.signingInput.utf8Data
			)
		)
	}

}

extension ECDSASigner {
	//the client doesn't verify JWTs
	func verify(
		_ signature: some DataProtocol,
		signs plaintext: some DataProtocol
	) throws -> Bool {
		let digest = SHA256.hash(data: plaintext)
		let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
		return publicKey.isValidSignature(signature, for: digest)
	}
}
