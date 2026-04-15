//
//  DPoPKey.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26.
//

import Crypto
import Foundation

public enum DPoPAlg: Codable, Hashable, Sendable {
	case es256
}

//keep this a primitive type
public struct DPoPKey: Codable, Hashable, Sendable {
	let alg: DPoPAlg
	let keyData: Data

	public static func generateP256() -> Self {
		.init(alg: .es256, keyData: P256.Signing.PrivateKey().rawRepresentation)
	}

	public init(alg: DPoPAlg, keyData: Data) {
		self.alg = alg
		self.keyData = keyData
	}

	func sign(payload: DPoPRequestPayload) throws -> JWT {
		switch alg {
		case .es256:
			try signSha256(
				keyType: "dpop+jwt",
				payload: payload
			)
		}
	}

	private func signSha256(
		keyType: String,
		payload: DPoPRequestPayload
	) throws -> JWT {

		let key = try P256.Signing.PrivateKey(rawRepresentation: keyData)

		return try ECDSASigner(key: key).sign(
			keyType: keyType,
			payload: payload,
		)
	}
}
