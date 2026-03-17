//
//  Base64Url.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/20/26.
//

import Foundation

/// Extension for making base64 representations of `Data` safe for
/// transmitting via URL query parameters
extension Data {
	/// Instantiates data by decoding a base64url string into base64
	///
	/// - Parameter string: A base64url encoded string
	init?(base64URLEncoded string: String) {
		self.init(base64Encoded: string.fromBase64URL)
	}

	/// Encodes the string into a base64url safe representation
	///
	/// - Returns: A string that is base64 encoded but made safe for passing
	///            in as a query parameter into a URL string
	func base64URLEncodedString() -> String {
		base64EncodedString().toBase64URL
	}
}

extension String {
	// Make base64 string safe for passing into URL query params
	var toBase64URL: String {
		self.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "=", with: "")
	}

	var fromBase64URL: String {
		self.replacingOccurrences(of: "_", with: "/")
			.replacingOccurrences(of: "-", with: "+")
			.base64padded
	}

	private var base64padded: String {
		let padding = 4 - count % 4
		guard (0..<4).contains(padding) else { return self }

		return self + String(repeating: "=", count: padding)
	}
}

extension DataProtocol {
	package func base64URLEncodedBytes() -> [UInt8] {
		Data(copyBytes()).base64EncodedData().base64URLEscaped().copyBytes()
	}
}

// MARK: Data Escape

extension Data {
	/// Converts base64 encoded data to a base64-url encoded data.
	///
	/// https://tools.ietf.org/html/rfc4648#page-7
	fileprivate mutating func base64URLEscape() {
		for idx in self.indices {
			switch self[idx] {
			case 0x2B:  // +
				self[idx] = 0x2D  // -
			case 0x2F:  // /
				self[idx] = 0x5F  // _
			default: break
			}
		}
		self = split(separator: 0x3D).first ?? .init()
	}

	/// Converts base64 encoded data to a base64-url encoded data.
	///
	/// https://tools.ietf.org/html/rfc4648#page-7
	fileprivate func base64URLEscaped() -> Data {
		var data = self
		data.base64URLEscape()
		return data
	}
}

extension DataProtocol {
	func copyBytes() -> [UInt8] {
		if let array = self.withContiguousStorageIfAvailable({ buffer in
			[UInt8](buffer)
		}) {
			return array
		} else {
			let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(
				capacity: self.count)
			self.copyBytes(to: buffer)
			defer { buffer.deallocate() }
			return [UInt8](buffer)
		}
	}
}
