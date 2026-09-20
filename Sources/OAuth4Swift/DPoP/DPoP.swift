//
//  DPoPKey.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26.
//

import Crypto
import Foundation
import GermConvenience
import SecretBytes

extension OAuth {
	public enum DPoP {
		public enum Alg: Codable, Hashable, Sendable {
			case es256
		}

		//This is for now, congruent to its archive
		//TODO: simplify this into an archive and
		public struct Key: Codable, Equatable, Sendable {
			public let alg: Alg

			/// The P-256 private scalar, in zeroizing custody. It is a secret,
			/// so it rides `swift-secret-bytes`' `@SecretField`: this type is
			/// `Codable` only into a `SecretArchive`; any other coder throws
			/// rather than writing the scalar plainly.
			@SecretField public var keyData: SecretBytes

			/// Generates a fresh P-256 signing key.
			///
			/// Non-failing on purpose: the wrap into `SecretBytes` can only fail
			/// on an empty byte string, and a generated P-256 scalar is always
			/// 32 bytes — so callers in non-throwing positions (a stored
			/// property, a test fixture) are not forced to `try!`.
			public static func generateP256() -> Self {
				guard
					let keyData = try? SecretBytes(
						bytes: P256.Signing.PrivateKey().rawRepresentation)
				else {
					preconditionFailure("a generated P-256 scalar is never empty")
				}
				return .init(alg: .es256, keyData: keyData)
			}

			public init(alg: Alg, keyData: SecretBytes) {
				self.alg = alg
				self.keyData = keyData
			}

			/// Builds from raw scalar bytes, wrapping them into zeroizing
			/// custody — the counterpart to reading `keyData` for a caller that
			/// holds the bytes as `Data` (a legacy decode, a test vector).
			public init(alg: Alg, rawKeyData: Data) throws {
				self.init(
					alg: alg,
					keyData: try SecretBytes(bytes: rawKeyData))
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
