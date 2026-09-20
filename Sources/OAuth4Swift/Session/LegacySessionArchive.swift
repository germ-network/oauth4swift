//
//  LegacySessionArchive.swift
//  OAuth4Swift
//

import Foundation
import SecretBytes

extension OAuth.SessionState {
	/// The **legacy plaintext** JSON shape of `OAuth.SessionState.Archive` —
	/// the form persisted before this package held its secrets in zeroizing
	/// custody: token values as plain `String`, the DPoP scalar as base64
	/// `Data` (the default `JSONEncoder`/`JSONDecoder` shapes).
	///
	/// It exists only to migrate an already-persisted blob. An app whose own
	/// archive nests the session archive embeds `LegacyArchive` where the live
	/// archive would go, decodes the whole tree with a plain `JSONDecoder`, and
	/// calls `archived()` to lift the secrets into `SecretBytes`. New archives
	/// never take this path — they ride `SecretArchive`/`@SecretField`, and
	/// this type deliberately carries no encoder.
	public struct LegacyArchive: Decodable {
		public let clientId: String
		public let dPopKey: LegacyDPoPKey?
		public let issuingServer: String
		public let grantScopes: [String]?
		public let tokenState: LegacyTokenState

		/// Lifts the legacy values into a live, zeroizing archive.
		public func archived() throws -> OAuth.SessionState.Archive {
			.init(
				clientId: clientId,
				dPopKey: try dPopKey?.archived(),
				issuingServer: issuingServer,
				grantScopes: grantScopes,
				tokenState: try tokenState.archived()
			)
		}
	}

	/// The legacy `OAuth.DPoP.Key` shape: `alg` in the enum's synthesized
	/// Codable form, `keyData` as base64 `Data`.
	public struct LegacyDPoPKey: Decodable {
		public let alg: OAuth.DPoP.Alg
		public let keyData: Data

		public func archived() throws -> OAuth.DPoP.Key {
			.init(alg: alg, keyData: try SecretBytes(bytes: keyData))
		}
	}

	/// The legacy shape of an access or refresh token: a plain `String` value.
	public struct LegacyToken: Decodable {
		public let value: String
		public let expiry: Date?
		public let fetchedOn: Date?

		func accessToken() throws -> OAuth.AccessToken {
			try .init(value: value, expiry: expiry, fetchedOn: fetchedOn)
		}

		func refreshToken() throws -> OAuth.RefreshToken {
			try .init(value: value, expiry: expiry, fetchedOn: fetchedOn)
		}
	}

	public struct LegacyTokenState: Decodable {
		public let grantExpiry: Date?
		public let accessToken: LegacyToken
		public let refreshToken: LegacyToken?
		public let scopes: [String]

		public func archived() throws -> OAuth.SessionState.TokenState {
			.init(
				accessToken: try accessToken.accessToken(),
				refreshToken: try refreshToken?.refreshToken(),
				scopes: scopes,
				grantExpiry: grantExpiry
			)
		}
	}
}

extension OAuth.SessionState.Archive {
	/// Decodes a legacy **plaintext** JSON archive — the pre-zeroizing shape,
	/// `LegacyArchive` — straight into the live, secret-bearing form.
	///
	/// A blob in the *current* form carries `@SecretField` secrets and is not
	/// JSON; it is read back through `SecretArchive.open(...).decode(...)`, not
	/// here. This is migration-only: it hands to the archive the plaintext the
	/// caller already held.
	public static func decodeLegacy(_ data: Data) throws -> Self {
		try JSONDecoder()
			.decode(OAuth.SessionState.LegacyArchive.self, from: data)
			.archived()
	}
}
