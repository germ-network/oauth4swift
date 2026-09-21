//
//  SessionState.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation
import GermConvenience
import SecretBytes

extension OAuth {
	protocol Token {
		/// The token's secret value, held in zeroizing storage.
		var value: SecretBytes { get }
		var expiry: Date? { get }
		//optional for both backward compatibility in decoding,
		//and to allow the adopter to efface it when storing
		var fetchedOn: Date? { get }

		init(value: SecretBytes, expiry: Date?, fetchedOn: Date?)
	}
}

extension OAuth.Token {
	var valid: Bool {
		guard let date = expiry else { return true }

		return date.timeIntervalSinceNow > 0
	}

	/// Builds from a wire `String`, validating its grammar and wrapping it into
	/// zeroizing custody.
	///
	/// The grammar enforced is `1*VSCHAR` — RFC 6749 A.12/A.17 — which is the
	/// token's own grammar; the narrower RFC 6750 §2.1 `b64token` shape belongs
	/// to a Bearer *credential* and is not enforced here. See
	/// `OAuth.TokenGrammar` for why.
	init(value: String, expiry: Date?, fetchedOn: Date?) throws {
		try OAuth.TokenGrammar.validate(value)
		self.init(
			value: try SecretBytes(utf8: value),
			expiry: expiry,
			fetchedOn: fetchedOn
		)
	}

	init(value: String, expiresIn: TimeInterval?) throws {
		try self.init(
			value: value,
			expiry: expiresIn?.expiryDateFromNow,
			fetchedOn: .now
		)
	}

	/// Materializes the token value as text, only for the call that needs a
	/// `String` (an `Authorization` header, a form field). Transient plaintext
	/// copy — see `SecretBytes.utf8String()`.
	var materializedValue: String {
		get throws { try value.utf8String() }
	}

	/// The full **Bearer credential** — scheme, one space, token — as RFC 6750
	/// §2.1 defines it: `credentials = "Bearer" 1*SP b64token`. The colon that
	/// appears in `Authorization: Bearer …` is the header *name* separator, not
	/// part of this value, so the scheme is followed by a single space and
	/// nothing else.
	///
	/// This is also where RFC 6750's grammar binds: `b64token =
	/// 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`. The token
	/// *itself* stays opaque — ingest enforces only RFC 6749's `1*VSCHAR` (see
	/// `OAuth.TokenGrammar`) — but at the point a Bearer credential is actually
	/// formed, the narrower grammar is exactly the one that governs, so it is
	/// enforced here rather than asserted about the issuer.
	///
	/// `materializedValue` remains the prefix-less, unvalidated exit for other
	/// transports (a form body, a revocation request).
	///
	/// - Throws: `OAuth.Errors.tokenNotBearerSafe` when the token falls outside
	///   the grammar, alongside any error from materializing it. Transient
	///   plaintext copy, as above.
	var asBearerToken: String {
		get throws {
			guard OAuth.TokenGrammar.isBearerSafe(value) else {
				throw OAuth.Errors.tokenNotBearerSafe
			}
			return "Bearer " + (try materializedValue)
		}
	}
}

extension OAuth {
	//while the types are structually identical, defining as separate types
	//to prevent use confusion
	public struct AccessToken: Codable, Equatable, Sendable {
		/// The token value, in zeroizing custody. It is a secret, so it rides
		/// `swift-secret-bytes`' `@SecretField`: this type is `Codable` only into
		/// a `SecretArchive`; any other coder throws rather than writing it plainly.
		@SecretField public var value: SecretBytes
		public let expiry: Date?
		public var fetchedOn: Date?

		// Public so a consumer can rebuild an archive it re-homed into zeroizing
		// custody without round-tripping through Codable (which keys on property
		// names and breaks silently on a rename).
		public init(value: SecretBytes, expiry: Date?, fetchedOn: Date?) {
			self.value = value
			self.expiry = expiry
			self.fetchedOn = fetchedOn
		}
	}

	/// Holds a refresh token value and optionally it's expiry
	public struct RefreshToken: Codable, Equatable, Sendable {
		/// The token value, in zeroizing custody — see `AccessToken.value`.
		@SecretField public var value: SecretBytes
		public let expiry: Date?
		public var fetchedOn: Date?

		/// Mirror of `AccessToken.init` — see its note.
		public init(value: SecretBytes, expiry: Date?, fetchedOn: Date?) {
			self.value = value
			self.expiry = expiry
			self.fetchedOn = fetchedOn
		}
	}

	//bundles the token value with its RFC 7009 token_type_hint so the pair
	//cannot disagree
	public enum RevocableToken: Sendable {
		case access(OAuth.AccessToken)
		case refresh(OAuth.RefreshToken)

		init(_ token: OAuth.AccessToken) {
			self = .access(token)
		}

		init(_ token: OAuth.RefreshToken) {
			self = .refresh(token)
		}

		/// Materializes the bundled token's value as text for the revocation
		/// request body. Transient plaintext copy — see `SecretBytes.utf8String()`.
		func materializedValue() throws -> String {
			switch self {
			case .access(let t): try t.materializedValue
			case .refresh(let t): try t.materializedValue
			}
		}

		var hint: String {
			switch self {
			case .access: "access_token"
			case .refresh: "refresh_token"
			}
		}
	}
}

extension OAuth.AccessToken: OAuth.Token {}

extension OAuth.RefreshToken: OAuth.Token {}

//defining in an extension to preserve the memberwise intializer
extension OAuth.RefreshToken {
	init?(value: String?, timeout: TimeInterval?) throws {
		//a present-but-empty refresh_token is treated as absent: some servers
		//send "" rather than omitting the field, and building an empty token
		//would clobber a refresh token the response meant to leave in force
		guard let value, !value.isEmpty else {
			return nil
		}
		try self.init(value: value, expiresIn: timeout)
	}

	//for a refresh response that leaves this token in force: the value carries
	//over, and refresh_token_timeout - which the server MAY send without a
	//refresh_token, in which case it applies to the presented one - restates
	//the expiry
	func refetched(timeout: TimeInterval?) -> Self {
		.init(
			value: value,
			expiry: timeout?.expiryDateFromNow ?? expiry,
			fetchedOn: .now
		)
	}
}

extension TimeInterval {
	init?(_ seconds: Int?) {
		guard let seconds else {
			return nil
		}
		self.init(seconds)
	}

	var expiryDateFromNow: Date {
		Date(timeIntervalSinceNow: self)
	}
}

//best way to express fixed key and variable accessToken is as a reference type
extension OAuth {
	public class SessionState {
		public let clientId: String
		public let issuingServer: String
		//not mandatory in OAuth 2.1
		public let dPoPState: DPoP.State?
		//stores the authorization grant scope:
		public let grantScopes: [String]?

		//mutable state
		public var tokenState: TokenState

		public init(
			clientId: String,
			issuingServer: String,
			dPoPState: DPoP.State?,
			grantScopes: [String]?,
			tokenState: TokenState
		) {
			self.clientId = clientId
			self.issuingServer = issuingServer
			self.dPoPState = dPoPState
			self.grantScopes = grantScopes
			self.tokenState = tokenState
		}

		public struct TokenState: Codable, Sendable {
			public var grantExpiry: Date?
			public var accessToken: AccessToken
			public var refreshToken: RefreshToken?

			//what is currently authorized on the last refresh
			public var scopes: [String]

			init(
				accessToken: AccessToken,
				refreshToken: RefreshToken? = nil,
				scopes: [String] = [],
				grantExpiresIn: TimeInterval? = nil
			) {
				self.accessToken = accessToken
				self.refreshToken = refreshToken
				self.scopes = scopes

				// Support for Authorization Grants with expiry:
				// https://www.ietf.org/archive/id/draft-ietf-oauth-refresh-token-expiration-01.html
				self.grantExpiry = grantExpiresIn?.expiryDateFromNow
			}

			// Public mirror of the above that stores an already-resolved
			// `grantExpiry`, so an archive re-homed into zeroizing custody
			// round-trips its expiry Date exactly rather than re-deriving it.
			public init(
				accessToken: AccessToken,
				refreshToken: RefreshToken? = nil,
				scopes: [String] = [],
				grantExpiry: Date? = nil
			) {
				self.accessToken = accessToken
				self.refreshToken = refreshToken
				self.scopes = scopes
				self.grantExpiry = grantExpiry
			}

			/// Determines if the token object is valid.
			///
			/// A token without an expiry is unconditionally valid.
			public var valid: Bool {
				guard let date = grantExpiry else { return true }

				return date.timeIntervalSinceNow > 0
			}
		}

		public func updated(tokenState: TokenState) {
			self.tokenState = tokenState
		}
	}
}

extension OAuth.SessionState {
	public struct Archive: Sendable, Codable {
		// Public so a consumer can re-home the archive (and its secrets) into
		// zeroizing custody without round-tripping through this type's Codable
		// shape — a bridge keyed on property names breaks silently on a rename.
		public let clientId: String
		public let dPopKey: OAuth.DPoP.Key?
		public let issuingServer: String

		//stores the authorization grant scope:
		public let grantScopes: [String]?
		public var tokenState: TokenState

		public init(
			clientId: String,
			dPopKey: OAuth.DPoP.Key?,
			issuingServer: String,
			grantScopes: [String]?,
			tokenState: TokenState
		) {
			self.clientId = clientId
			self.dPopKey = dPopKey
			self.issuingServer = issuingServer

			self.grantScopes = grantScopes
			self.tokenState = tokenState
		}
	}

	public convenience init(
		archive: Archive,
		dpopDecoder: OAuth.DPoP.NonceDecoder?
	) throws {
		self.init(
			clientId: archive.clientId,
			issuingServer: archive.issuingServer,
			dPoPState: try .restore(
				archivedKey: archive.dPopKey,
				decoder: dpopDecoder
			),
			grantScopes: archive.grantScopes,
			tokenState: archive.tokenState
		)
	}

	public var archive: Archive {
		get throws {
			.init(
				clientId: clientId,
				dPopKey: dPoPState?.signingKey,
				issuingServer: issuingServer,
				grantScopes: grantScopes,
				tokenState: tokenState
			)
		}
	}
}

extension OAuth.DPoP.State {
	static func restore(
		archivedKey: OAuth.DPoP.Key?,
		decoder: OAuth.DPoP.NonceDecoder?
	) throws -> OAuth.DPoP.State? {
		switch (archivedKey, decoder) {
		case (nil, nil):
			nil
		case (.some(let key), .some(let decoder)):
			.init(signingKey: key, decoder: decoder)
		default:
			throw OAuth.DPoP.Errors.mismatchedArchive
		}
	}
}

//for tokenValidator
extension OAuth.SessionState {
	public struct Snapshot: Sendable {
		public let issuingServer: String
		//stores the authorization grant scope:
		public let grantScopes: [String]?

		public init(
			issuingServer: String,
			grantScopes: [String]?
		) {
			self.issuingServer = issuingServer
			self.grantScopes = grantScopes
		}
	}

	public var snapshot: Snapshot {
		.init(
			issuingServer: issuingServer,
			grantScopes: grantScopes
		)
	}
}

extension OAuth.SessionState.Archive {
	static public func mock() throws -> Self {
		.init(
			clientId: "app.example.com",
			dPopKey: .generateP256(),
			issuingServer: "issuer.example.com",
			grantScopes: nil,
			tokenState: try .mock()
		)
	}
}

extension OAuth.SessionState.TokenState {
	//takes the place of a public memberwise intializer
	static public func mock(
		accessToken: OAuth.AccessToken? = nil,
		refreshToken: OAuth.RefreshToken? = nil,
		scopes: [String] = [],
		grantExpiresIn: TimeInterval? = nil
	) throws -> Self {
		.init(
			accessToken: try accessToken ?? .mock(),
			refreshToken: refreshToken,
			scopes: scopes,
			grantExpiresIn: grantExpiresIn
		)
	}
}

extension OAuth.AccessToken {
	static public func mock(
		value: String = UUID().uuidString,
		expiresIn: TimeInterval? = nil
	) throws -> Self {
		try .init(value: value, expiresIn: expiresIn)
	}
}

extension OAuth.RefreshToken {
	static public func mock(
		value: String = UUID().uuidString,
		expiresIn: TimeInterval? = nil
	) throws -> Self {
		try .init(value: value, expiresIn: expiresIn)
	}
}
