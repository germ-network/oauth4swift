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

	@Test("an empty token is refused: `1*VSCHAR` requires at least one character")
	func emptyTokenRejected() throws {
		#expect {
			_ = try OAuth.AccessToken(value: "", expiry: nil, fetchedOn: nil)
		} throws: { error in
			guard case OAuth.Errors.malformedToken = error else { return false }
			return true
		}
	}

	@Test("a token outside the RFC 6749 grammar is refused on ingest")
	func malformedTokenRejected() throws {
		//VSCHAR is %x20-7E: a control character or a non-ASCII scalar is outside it
		#expect {
			_ = try OAuth.AccessToken(value: "bad\ttoken", expiry: nil, fetchedOn: nil)
		} throws: { error in
			guard case OAuth.Errors.malformedToken = error else { return false }
			return true
		}
		#expect {
			_ = try OAuth.RefreshToken(value: "tökén", expiry: nil, fetchedOn: nil)
		} throws: { error in
			guard case OAuth.Errors.malformedToken = error else { return false }
			return true
		}
		//space is IN VSCHAR, so it is accepted — the grammar is the RFC's, not a guess
		#expect(OAuth.TokenGrammar.isValid("a b"))
		#expect(OAuth.TokenGrammar.isValid("tökén") == false)
	}

	@Test("asBearerToken materializes a b64token, and rejects one outside the grammar")
	func asBearerTokenEnforcesTheCredentialGrammar() throws {
		//RFC 6750 §2.1 b64token: ALPHA / DIGIT / - . _ ~ + / , then *"="
		let safe = try OAuth.AccessToken(value: "at-123._~+/=", expiry: nil, fetchedOn: nil)
		#expect(try safe.asBearerToken == "at-123._~+/=")
		#expect(OAuth.TokenGrammar.isBearerSafe(safe.value))

		//VSCHAR-valid (so ingest accepts it) but outside b64token, so it cannot
		//be carried as a Bearer credential — the boundary refuses it
		let opaque = try OAuth.RefreshToken(value: "a,b", expiry: nil, fetchedOn: nil)
		#expect(OAuth.TokenGrammar.isBearerSafe(opaque.value) == false)
		#expect {
			_ = try opaque.asBearerToken
		} throws: { error in
			guard case OAuth.Errors.tokenNotBearerSafe = error else { return false }
			return true
		}

		//materializedValue is the unvalidated exit, for the transports where the
		//Bearer grammar does not govern
		#expect(try opaque.materializedValue == "a,b")
	}

	@Test("a legacy plaintext JSON archive decodes into zeroizing custody")
	func legacyDecode() throws {
		let key = OAuth.DPoP.Key.generateP256()
		let keyDataBase64 = key.keyData.withUnsafeBytes {
			Data($0).base64EncodedString()
		}
		//the DPoP alg rides the enum's own synthesized Codable, exactly as the
		//legacy encoder wrote it — derive it rather than hardcode the shape
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
		#expect(try archive.tokenState.accessToken.value.utf8String() == "legacy-access")
		let refreshValue = archive.tokenState.refreshToken.map {
			try? $0.value.utf8String()
		}
		#expect(refreshValue == "legacy-refresh")

		//and the decoded archive rides the sealed form from here on
		let restored = try SecretArchive(encoding: archive)
			.decode(OAuth.SessionState.Archive.self)
		#expect(restored.dPopKey?.keyData == key.keyData)
	}

	@Test("a base64-shaped legacy token is read as the token, not decoded")
	func legacyBase64ShapedTokenIsLiteral() throws {
		//the legacy token was written as a JSON string, and OAuth tokens are
		//base64url-shaped — so a reader that "tried Data first" would silently
		//turn this token into different bytes. The string is the token.
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
		#expect(try archive.tokenState.accessToken.value.utf8String() == token)
	}
}
