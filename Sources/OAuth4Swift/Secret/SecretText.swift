//
//  SecretText.swift
//  OAuth4Swift
//

import Foundation
import SecretBytes

extension OAuth {
	/// The one bridge between a held secret's zeroizing bytes and its UTF-8
	/// text form — the single place the conversion is defined, rather than an
	/// ad-hoc `.utf8` at each call site.
	///
	/// OAuth token values are RFC 6749 §5.1 `token68`/`1*VSCHAR` — ASCII by
	/// grammar — and DPoP key material is a fixed-width byte string, so UTF-8
	/// is a lossless, unambiguous round-trip in both directions.
	///
	/// `SecretBytes` deliberately exposes no text accessor; the `String`
	/// `string(from:)` returns is a plaintext copy with none of that type's
	/// scrubbing. It exists only for the call that needs a `String` — an
	/// `Authorization` header value, a form field — and must be transient:
	/// never persisted, never logged, never retained.
	public enum SecretText {
		/// Wraps text into zeroizing custody.
		///
		/// - Throws: `SecretBytesError.emptySecret` for an empty string, which
		///   `SecretBytes` cannot represent (a zero-byte secret compares unequal
		///   to itself). An empty token is therefore a constructible-time
		///   refusal rather than a stored empty secret.
		public static func secretBytes(from string: String) throws -> SecretBytes {
			try SecretBytes(bytes: Data(string.utf8))
		}

		/// Materializes a secret as UTF-8 text — a transient plaintext copy;
		/// see the note on this type.
		///
		/// - Throws: `OAuth.Errors.secretNotUTF8` if the bytes are not valid
		///   UTF-8. Substituting U+FFFD would silently corrupt a credential, so
		///   this refuses instead.
		public static func string(from secret: SecretBytes) throws -> String {
			try secret.withUnsafeBytes { bytes in
				guard let string = String(bytes: bytes, encoding: .utf8) else {
					throw OAuth.Errors.secretNotUTF8
				}
				return string
			}
		}
	}
}
