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
		/// The identifier's canonical form: scheme, host, non-default port, and
		/// path with its terminating "/" removed. RFC 8414 §3.3 and RFC 9728 §3.3
		/// require the response's `issuer` / `resource` claim to match this
		/// exactly.
		public let canonicalIdentifier: String
	}

	/// Builds a `.well-known` discovery request by inserting `segment` between
	/// the host and the existing path, per RFC 9728 §3.1 and RFC 8414 §3.1.
	///
	/// Throws `invalidResourceIdentifier` rather than silently normalizing when
	/// the URL carries userinfo, a query, a fragment, or a "." / ".." / empty
	/// path segment — RFC 8414 §2 and RFC 9728 §2 disallow all of these in an
	/// issuer or resource identifier, and coercing them could send the request
	/// somewhere other than the identifier the caller believes it's fetching.
	public func insertingWellKnownSegment(_ segment: String) throws -> WellKnownDiscovery {
		guard
			var components = URLComponents(url: self, resolvingAgainstBaseURL: false),
			components.scheme != nil,
			let host = components.host, !host.isEmpty
		else {
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
		let pathSegments = existingPath.split(
			separator: "/", omittingEmptySubsequences: false
		)
		.dropFirst()
		guard pathSegments.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
			throw OAuth.Errors.invalidResourceIdentifier
		}

		components.percentEncodedPath = existingPath
		let canonicalIdentifier = try components.url.tryUnwrap(OAuth.Errors.missingHost)
			.absoluteString

		components.percentEncodedPath = "/" + segment + existingPath
		let discoveryURL = try components.url.tryUnwrap(OAuth.Errors.missingHost)

		return WellKnownDiscovery(
			url: discoveryURL, canonicalIdentifier: canonicalIdentifier)
	}
}
