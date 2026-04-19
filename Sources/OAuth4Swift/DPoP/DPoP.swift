//
//  DPoPKey.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26.
//

import Crypto
import Foundation
import GermConvenience

extension OAuth {
	public enum DPoP {
		public enum Alg: Codable, Hashable, Sendable {
			case es256
		}
		
		//This is for now, congruent to its archive
		//TODO: simplify this into an archive and
		public struct Key: Codable, Hashable, Sendable {
			let alg: Alg
			let keyData: Data

			public static func generateP256() -> Self {
				.init(alg: .es256, keyData: P256.Signing.PrivateKey().rawRepresentation)
			}

			public init(alg: Alg, keyData: Data) {
				self.alg = alg
				self.keyData = keyData
			}

			func sign(payload: RequestPayload) throws -> JWT {
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
				payload: RequestPayload
			) throws -> JWT {

				let key = try P256.Signing.PrivateKey(rawRepresentation: keyData)

				return try ECDSASigner(key: key).sign(
					keyType: keyType,
					payload: payload,
				)
			}
		}

	}
}



