//
//  TokenGrammar.swift
//  OAuth4Swift
//

import Foundation
import SecretBytes

extension OAuth {
	/// The token grammars in play, and which one this package enforces where.
	///
	/// RFC 6749 defines the token strings themselves over `VSCHAR`: Appendix
	/// A.12 `access-token = 1*VSCHAR`, A.17 `refresh-token = 1*VSCHAR`, with
	/// `VSCHAR = %x20-7E` (Appendix A). Sections 1.4 and 1.5 describe the value
	/// as *usually opaque to the client*, and §10.3 puts the obligation to mint
	/// unguessable tokens on the authorization server — so the issuer, not the
	/// client, decides what a token looks like inside that grammar.
	/// `validate(_:)` enforces exactly that grammar, on ingest.
	///
	/// RFC 6750 §2.1 defines a narrower set for one transport:
	/// `b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
	/// with `credentials = "Bearer" 1*SP b64token`. That constrains a Bearer
	/// *credential*, not the token. It is therefore **not** enforced on ingest —
	/// a conforming authorization server may issue a token outside it, and
	/// refusing one the server minted would be this client pretending to know
	/// better than the issuer. `isBearerSafe(_:)` is exposed for a caller that
	/// does need to know whether a value can be carried that way.
	public enum TokenGrammar {
		/// Enforces RFC 6749 A.12/A.17: `1*VSCHAR`, `VSCHAR = %x20-7E`.
		///
		/// - Throws: `OAuth.Errors.malformedToken` for an empty value or one
		///   carrying a character outside the range.
		public static func validate(_ value: String) throws {
			guard isValid(value) else { throw OAuth.Errors.malformedToken }
		}

		/// RFC 6749 A.12/A.17: at least one character, all within `%x20-7E`.
		///
		/// Tested over Unicode scalars, which is what the RFC's ABNF is
		/// defined over (Appendix A) — a scalar outside the range is outside
		/// the grammar whatever its UTF-8 length.
		public static func isValid(_ value: String) -> Bool {
			guard !value.isEmpty else { return false }
			return value.unicodeScalars.allSatisfy { (0x20...0x7E).contains($0.value) }
		}

		/// RFC 6750 §2.1 `b64token`: one or more of `ALPHA / DIGIT / - . _ ~ + /`,
		/// then zero or more `=`.
		public static func isBearerSafe(_ value: SecretBytes) -> Bool {
			value.withUnsafeBytes { bytes in
				guard !bytes.isEmpty else { return false }

				//trailing *"=" is allowed, but the 1* part must still be present
				var end = bytes.count
				while end > 0, bytes[end - 1] == UInt8(ascii: "=") { end -= 1 }
				guard end >= 1 else { return false }

				for index in 0..<end where !isB64TokenByte(bytes[index]) {
					return false
				}
				return true
			}
		}

		private static func isB64TokenByte(_ byte: UInt8) -> Bool {
			switch byte {
			case UInt8(ascii: "A")...UInt8(ascii: "Z"),
				UInt8(ascii: "a")...UInt8(ascii: "z"),
				UInt8(ascii: "0")...UInt8(ascii: "9"),
				UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"),
				UInt8(ascii: "~"), UInt8(ascii: "+"), UInt8(ascii: "/"):
				return true
			default:
				return false
			}
		}
	}
}
