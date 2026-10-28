//
//  JWTLexiconLite.swift
//  OAuth
//
//  Created by Anna Mistele on 4/23/25.
//

import Base64
import Crypto
import Foundation

//super compact es256 JWT implmentation instead of BYO JWT signer

struct JWT {
	let header: String
	let payload: String
	let signature: String

	var string: String {
		header + [JWT.period] + payload + [JWT.period] + signature
	}

	var signingInput: String {
		header + [JWT.period] + payload
	}
}

extension JWT {
	static var period: Character {
		.init(".")
	}

	struct JWK: Sendable, Codable {
		let kty: String
		let crv: String
		let x: String
		let y: String

		init(key: P256.Signing.PublicKey) throws {
			// Public key consists of 04 | X | Y where X and Y are the same length
			// (Which, for P256, is 256 / 8 = 32 bytes each.)
			// https://developer.apple.com/forums/thread/680554
			let componentSize = JWT.Constants.keySize / 8
			let keyBytes = key.x963Representation
			guard keyBytes.count == (componentSize * 2 + 1) else {
				throw JWTError.badKey
			}
			guard keyBytes[0] == JWT.Constants.keyMarker else {
				throw JWTError.badKey
			}

			self.kty = "EC"
			self.crv = "P-256"
			self.x = Base64.encodedString(
				keyBytes.subdata(in: 1..<(componentSize + 1)),
				variant: .url,
				pad: .unpadded
			)
			self.y = Base64.encodedString(
				keyBytes.subdata(in: (componentSize + 1)..<(componentSize * 2 + 1)),
				variant: .url,
				pad: .unpadded
			)
		}
	}

	struct Header: Codable {
		let typ: String
		let alg: String
		let jwk: JWK

		init(
			typ: String?,
			alg: String = Constants.ecdsaSignerAlg,
			jwk: JWK
		) {
			self.typ = typ ?? "JWT"
			self.alg = alg
			self.jwk = jwk
		}
	}

	struct Constants {
		static let keySize = 256
		static let keyMarker = 0x04
		static let ecdsaSignerAlg = "ES256"
	}
}

extension Encodable {
	var jwtEncoded: String {
		get throws {
			let encoder = JSONEncoder()
			encoder.dateEncodingStrategy = .secondsSince1970
			let encodedHeader = Data(
				Base64.encode(try encoder.encode(self), variant: .url))

			return try String(
				data: .init(encodedHeader),
				encoding: .utf8
			).unwrapped
		}
	}
}

enum JWTError: Error, Equatable {
	case badKey
}
