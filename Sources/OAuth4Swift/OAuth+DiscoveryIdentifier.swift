//
//  OAuth+DiscoveryIdentifier.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 8/19/26.
//

import Foundation
import GermConvenience

extension OAuth {
	/// Where an authorization server's metadata is discovered, mirroring
	/// oauth4webapi's `discoveryRequest` `algorithm` option. Unlike oauth4webapi,
	/// which defaults to `.oidc`, `OAuth.discoveryRequest` defaults to `.oauth2`
	/// (RFC 8414), the location atproto requires.
	public enum DiscoveryAlgorithm: Sendable {
		/// OpenID Connect Discovery 1.0 §4: `/.well-known/openid-configuration`
		/// appended after the issuer's path.
		case oidc
		/// RFC 8414 §3.1: `/.well-known/oauth-authorization-server` inserted
		/// between the host and the issuer's path.
		case oauth2
	}

	/// An issuer or resource identifier and the URL its metadata is discovered
	/// at. RFC 8414 §3.3, RFC 9728 §3.3 and OpenID Connect Discovery 1.0 §4.3
	/// require the discovered `issuer`/`resource` to be *identical* to the
	/// identifier the discovery URL was built from, so only the path and query
	/// are touched; the scheme and authority are kept exactly as given.
	struct DiscoveryIdentifier: Sendable {
		/// The metadata document to discover for the identifier.
		enum Metadata: Sendable {
			/// RFC 9728 §3.1 — Protected Resource Metadata.
			case protectedResource
			/// RFC 8414 §3.1 or OpenID Connect Discovery 1.0 §4.
			case authorizationServer(DiscoveryAlgorithm)
		}

		let discoveryURL: URL

		/// Throws `missingScheme`/`missingHost` if either is absent,
		/// `insecureScheme` for anything but https, and `invalidResourceIdentifier`
		/// for userinfo, a fragment, or a query on an issuer (RFC 8414 §2; RFC 9728
		/// §3.1 allows a query on a resource).
		init(_ url: URL, for metadata: Metadata) throws {
			guard
				var components = URLComponents(
					url: url, resolvingAgainstBaseURL: false),
				let scheme = components.scheme, !scheme.isEmpty
			else {
				throw OAuth.Errors.missingScheme
			}
			guard components.host?.isEmpty == false else {
				throw OAuth.Errors.missingHost
			}
			guard scheme == "https" else {
				throw OAuth.Errors.insecureScheme
			}
			guard
				components.user == nil,
				components.password == nil,
				components.fragment == nil
			else {
				throw OAuth.Errors.invalidResourceIdentifier
			}

			let path = components.percentEncodedPath
			switch metadata {
			case .protectedResource:
				// RFC 9728 §3.1: only the slash following the host is removed
				components.percentEncodedPath =
					"/.well-known/oauth-protected-resource"
					+ (path == "/" ? "" : path)
			case .authorizationServer(let algorithm):
				guard components.percentEncodedQuery == nil else {
					throw OAuth.Errors.invalidResourceIdentifier
				}
				// RFC 8414 §3.1, OpenID Connect Discovery 1.0 §4: any terminating slash
				let trimmed = path.hasSuffix("/") ? String(path.dropLast()) : path
				components.percentEncodedPath =
					switch algorithm {
					case .oauth2:
						"/.well-known/oauth-authorization-server" + trimmed
					case .oidc: trimmed + "/.well-known/openid-configuration"
					}
			}
			self.discoveryURL = try components.url
				.unwrap(or: OAuth.Errors.invalidResourceIdentifier)
		}
	}
}
