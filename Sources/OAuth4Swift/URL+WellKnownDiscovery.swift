//
//  URL+WellKnownDiscovery.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 8/19/26.
//

import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

extension OAuth {
	/// RFC 9728 Section 3.1 — Protected Resource Metadata well-known suffix.
	public static let wellKnownProtectedResource = ".well-known/oauth-protected-resource"
	/// RFC 8414 Section 3.1 — Authorization Server Metadata well-known suffix.
	public static let wellKnownAuthorizationServer = ".well-known/oauth-authorization-server"
}

extension URL {
	/// A `.well-known` discovery request built from a resource or issuer identifier.
	public struct WellKnownDiscovery: Sendable {
		/// `segment` inserted between the host and the source URL's path, per
		/// RFC 9728 §3.1 / RFC 8414 §3.1.
		public let url: URL
		/// `segment` appended after the source URL's path — the pre-RFC location
		/// some deployed servers still serve.
		public let legacyURL: URL
		/// The identifier's canonical form, per `canonicalDiscoveryIdentifier()`.
		public let canonicalIdentifier: String
	}

	/// Builds a `.well-known` discovery request by inserting `segment` between
	/// the host and the existing path, per RFC 9728 §3.1 and RFC 8414 §3.1.
	public func insertingWellKnownSegment(_ segment: String) throws -> WellKnownDiscovery {
		let canonicalIdentifier = try canonicalDiscoveryIdentifier()

		// canonicalDiscoveryIdentifier() already validated scheme/host/etc., so this can't fail.
		guard var components = URLComponents(url: self, resolvingAgainstBaseURL: false)
		else {
			throw OAuth.Errors.missingHost
		}
		var existingPath = components.percentEncodedPath
		if existingPath.hasSuffix("/") {
			existingPath.removeLast()
		}

		components.percentEncodedPath = "/" + segment + existingPath
		let discoveryURL = try components.url.tryUnwrap(OAuth.Errors.missingHost)

		components.percentEncodedPath = existingPath + "/" + segment
		let legacyURL = try components.url.tryUnwrap(OAuth.Errors.missingHost)

		return WellKnownDiscovery(
			url: discoveryURL,
			legacyURL: legacyURL,
			canonicalIdentifier: canonicalIdentifier
		)
	}

	/// The RFC 8414 §3.3 / RFC 9728 §3.3 canonical form of an issuer/resource
	/// identifier: lowercased scheme and host, default port removed, a single
	/// terminating path slash removed, and each path segment percent-decoded,
	/// Unicode-NFC-normalized, then re-encoded with a fixed, uppercase-hex
	/// encoding. Comparing two identifiers' canonical forms is robust to
	/// superficial differences (host case, default port, percent-encoding hex
	/// case, Unicode normalization form) that would otherwise make two
	/// equivalent identifiers compare unequal — this is what a discovered
	/// `issuer`/`resource` claim is checked against.
	///
	/// A decoded segment is re-encoded with "/" excluded from the allowed set,
	/// so a segment that decodes to contain "/" (from an original `%2F`) stays
	/// encoded rather than becoming a path separator on the next parse — an
	/// encode/decode round trip must not change the number of segments.
	///
	/// Throws `missingScheme`/`missingHost` if either is absent, and
	/// `invalidResourceIdentifier` for userinfo, a query, a fragment, or a
	/// "."/".."/empty/undecodable path segment (RFC 8414 §2 / RFC 9728 §2
	/// disallow all of these in an issuer or resource identifier).
	public func canonicalDiscoveryIdentifier() throws -> String {
		guard
			let components = URLComponents(url: self, resolvingAgainstBaseURL: false),
			let scheme = components.scheme, !scheme.isEmpty
		else {
			throw OAuth.Errors.missingScheme
		}
		guard let host = components.host, !host.isEmpty else {
			throw OAuth.Errors.missingHost
		}
		guard
			components.user == nil,
			components.password == nil,
			components.query == nil,
			components.fragment == nil
		else {
			throw OAuth.Errors.invalidResourceIdentifier
		}

		var existingPath = components.percentEncodedPath
		if existingPath.hasSuffix("/") {
			existingPath.removeLast()
		}
		let rawSegments = existingPath.split(
			separator: "/", omittingEmptySubsequences: false
		)
		.dropFirst()
		let normalizedSegments = try rawSegments.map { try normalizedPathSegment($0) }

		var canonicalComponents = URLComponents()
		canonicalComponents.scheme = scheme.lowercased()
		canonicalComponents.host = host.lowercased()
		canonicalComponents.port = components.port
		canonicalComponents.percentEncodedPath = normalizedSegments.map { "/" + $0 }
			.joined()

		guard let canonicalURL = canonicalComponents.url else {
			throw OAuth.Errors.invalidResourceIdentifier
		}
		canonicalComponents.port = canonicalURL.nonDefaultHTTPort()
		return try canonicalComponents.url.tryUnwrap(OAuth.Errors.invalidResourceIdentifier)
			.absoluteString
	}
}

private let pathSegmentAllowed = CharacterSet.urlPathAllowed.subtracting(
	CharacterSet(charactersIn: "/")
)

private func normalizedPathSegment(_ raw: Substring) throws -> String {
	guard
		let decoded = String(raw).removingPercentEncoding,
		!decoded.isEmpty, decoded != ".", decoded != ".."
	else {
		throw OAuth.Errors.invalidResourceIdentifier
	}
	return try decoded.precomposedStringWithCanonicalMapping
		.addingPercentEncoding(withAllowedCharacters: pathSegmentAllowed)
		.tryUnwrap(OAuth.Errors.invalidResourceIdentifier)
}
