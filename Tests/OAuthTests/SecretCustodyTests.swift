//
//  SecretCustodyTests.swift
//  OAuth4Swift
//
//  Proves the three properties the secret-custody rework is about: the
//  archive's secrets survive a `SecretArchive` round-trip byte-for-byte, a
//  plain coder refuses to write them, and a legacy plaintext archive still
//  decodes into the zeroizing form.
//

import Foundation
import SecretBytes
import Testing

@testable import OAuth4Swift

@Suite("Session archive secret custody")
struct SecretCustodyTests {
	private func mockArchive() throws -> OAuth.SessionState.Archive {
		.init(
			clientId: "app.example.com",
			dPopKey: .generateP256(),
			issuingServer: "issuer.example.com",
			grantScopes: ["atproto"],
			tokenState: try .mock(
				accessToken: try .mock(value: "access-token-abc"),
				refreshToken: try .mock(value: "refresh-token-xyz"),
				scopes: ["atproto"]
			)
		)
	}

	private func plaintext(of secret: SecretBytes) -> String {
		secret.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
	}

	@Test("secrets restore byte-for-byte through a SecretArchive round-trip")
	func secretArchiveRoundTrip() throws {
		let archive = try mockArchive()

		let restored = try SecretArchive(encoding: archive)
			.decode(OAuth.SessionState.Archive.self)

		// plain state stays plain and intact
		#expect(restored.clientId == archive.clientId)
		#expect(restored.issuingServer == archive.issuingServer)
		#expect(restored.grantScopes == archive.grantScopes)

		// secrets restore into zeroizing storage, byte-for-byte
		#expect(restored.dPopKey?.keyData == archive.dPopKey?.keyData)
		#expect(restored.dPopKey?.alg == archive.dPopKey?.alg)
		#expect(
			restored.tokenState.accessToken.value
				== archive.tokenState.accessToken.value)
		#expect(
			restored.tokenState.refreshToken?.value
				== archive.tokenState.refreshToken?.value)
		#expect(plaintext(of: restored.tokenState.accessToken.value) == "access-token-abc")
	}

	@Test("a plain coder refuses to write the secrets")
	func plainCoderThrows() throws {
		let archive = try mockArchive()
		#expect(throws: SecretArchiveError.secretOutsideSecretArchive) {
			_ = try JSONEncoder().encode(archive)
		}
		// each secret-bearing sub-struct refuses on its own, so this fails the
		// day any single field is de-classified back to a plain type
		#expect(throws: SecretArchiveError.secretOutsideSecretArchive) {
			_ = try JSONEncoder().encode(try OAuth.AccessToken.mock(value: "t"))
		}
		#expect(throws: SecretArchiveError.secretOutsideSecretArchive) {
			_ = try JSONEncoder().encode(OAuth.DPoP.Key.generateP256())
		}
	}

	@Test("SecretText round-trips a token value losslessly")
	func secretTextRoundTrip() throws {
		let original = "abc-123_XYZ.~"
		let secret = try OAuth.SecretText.secretBytes(from: original)
		#expect(try OAuth.SecretText.string(from: secret) == original)
	}

	@Test("an empty token cannot be placed in zeroizing custody")
	func emptyTokenRejected() throws {
		#expect(throws: SecretBytesError.emptySecret) {
			_ = try OAuth.SecretText.secretBytes(from: "")
		}
	}

	@Test("a legacy plaintext JSON archive decodes into zeroizing custody")
	func legacyDecode() throws {
		let key = OAuth.DPoP.Key.generateP256()
		let keyDataBase64 = key.keyData.withUnsafeBytes {
			Data($0).base64EncodedString()
		}
		// the DPoP alg rides the enum's own synthesized Codable, exactly as the
		// legacy encoder wrote it — derive it rather than hardcode the shape
		let algJSON = String(
			decoding: try JSONEncoder().encode(OAuth.DPoP.Alg.es256),
			as: UTF8.self)

		let json = """
			{
			  "clientId": "app.example.com",
			  "issuingServer": "issuer.example.com",
			  "grantScopes": ["atproto"],
			  "dPopKey": { "alg": \(algJSON), "keyData": "\(keyDataBase64)" },
			  "tokenState": {
			    "scopes": ["atproto"],
			    "accessToken": { "value": "legacy-access", "expiry": 790000000.0, "fetchedOn": 789000000.0 },
			    "refreshToken": { "value": "legacy-refresh", "expiry": 790000000.0 }
			  }
			}
			"""

		let archive = try OAuth.SessionState.Archive.decodeLegacy(Data(json.utf8))

		#expect(archive.clientId == "app.example.com")
		#expect(archive.grantScopes == ["atproto"])
		#expect(archive.dPopKey?.keyData == key.keyData)
		#expect(plaintext(of: archive.tokenState.accessToken.value) == "legacy-access")
		let refreshValue = archive.tokenState.refreshToken.map { plaintext(of: $0.value) }
		#expect(refreshValue == "legacy-refresh")

		// and the decoded archive rides the sealed form from here on
		let restored = try SecretArchive(encoding: archive)
			.decode(OAuth.SessionState.Archive.self)
		#expect(restored.dPopKey?.keyData == key.keyData)
	}

	@Test("a base64-shaped legacy token is read as the token, not decoded")
	func legacyBase64ShapedTokenIsLiteral() throws {
		// The legacy token was written as a JSON string, and OAuth tokens are
		// base64url-shaped — so a reader that "tried Data first" would silently
		// turn this token into different bytes. The string is the token.
		let token = Data("token-bytes-encoded".utf8).base64EncodedString()

		let json = """
			{
			  "clientId": "app.example.com",
			  "issuingServer": "issuer.example.com",
			  "tokenState": {
			    "scopes": [],
			    "accessToken": { "value": "\(token)" }
			  }
			}
			"""

		let archive = try OAuth.SessionState.Archive.decodeLegacy(Data(json.utf8))
		#expect(
			try OAuth.SecretText.string(from: archive.tokenState.accessToken.value)
				== token)
	}
}
