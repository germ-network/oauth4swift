//
//  ECDSASigner.swift
//  OAuth
//
//  Created by Anna Mistele on 4/24/25.
//

import Crypto
import Foundation

struct ECDSASigner {
	let publicKey: P256.Signing.PublicKey
	private let privateKey: P256.Signing.PrivateKey?

	init(key: P256.Signing.PrivateKey) {
		self.privateKey = key
		self.publicKey = key.publicKey
	}

	func sign(
		keyType: String,
		payload: some Encodable,
	) throws -> JWT {
		let headerEncoded = try JWT.Header(
			typ: keyType,
			jwk: JWT.JWK(key: publicKey)
		).jwtEncoded
		let payloadEncoded = try payload.jwtEncoded

		let signatureInput = (headerEncoded + [JWT.period] + payloadEncoded).utf8
		let signatureData = try sign(Data(signatureInput))

		return .init(
			header: headerEncoded,
			payload: payloadEncoded,
			signature: signatureData.base64URLEncodedString()
		)
	}

	private func sign(_ plaintext: some DataProtocol) throws -> Data {
		guard let privateKey else {
			throw JWTError.badKey
		}
		let digest = SHA256.hash(data: plaintext)
		let signature = try privateKey.signature(for: digest)
		return signature.rawRepresentation
	}
}
