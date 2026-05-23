//
//  SessionState.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation
import GermConvenience

extension OAuth {
	protocol Token {
		var expiry: Date? { get }
		//optional for both backward compatibility in decoding,
		//and to allow the adopter to efface it when rtoring
		var fetchedOn: Date? { get }

		init(value: String, expiry: Date?, fetchedOn: Date?)
	}
}

extension OAuth.Token {
	var valid: Bool {
		guard let date = expiry else { return true }

		return date.timeIntervalSinceNow > 0
	}

	init(value: String, expiresIn: TimeInterval?) {
		self.init(
			value: value,
			expiry: expiresIn?.expiryDateFromNow,
			fetchedOn: .now
		)
	}
}

extension OAuth {
	//while the types are structually identical, defining as separate types
	//to prevent use confusion
	public struct AccessToken: Codable, Hashable, Sendable {
		public let value: String
		public let expiry: Date?
		public var fetchedOn: Date?
	}

	/// Holds a refresh token value and optionally it's expiry
	public struct RefreshToken: Codable, Hashable, Sendable {
		public let value: String
		public let expiry: Date?
		public var fetchedOn: Date?
	}
}

extension OAuth.AccessToken: OAuth.Token {}

extension OAuth.RefreshToken: OAuth.Token {}

//defining in an extension to preserve the memberwise intializer
extension OAuth.RefreshToken {
	init?(value: String?, timeout: TimeInterval?) {
		guard let value else {
			return nil
		}
		self.init(value: value, expiresIn: timeout)
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
		//stores the additional parameters from the TokenResponse
		public let additionalParams: [String: String]?
		//not mandatory in OAuth 2.1
		public let dPoPState: DPoP.State?
		//stores the authorization grant scope:
		public let grantScopes: [String]?

		//mutable state
		var tokenState: TokenState
		public var accessToken: AccessToken {
			tokenState.accessToken
		}

		public init(
			clientId: String,
			issuingServer: String,
			additionalParams: [String: String]? = nil,
			dPoPState: DPoP.State?,
			grantScopes: [String]?,
			tokenState: TokenState
		) {
			self.clientId = clientId
			self.issuingServer = issuingServer
			self.additionalParams = additionalParams
			self.dPoPState = dPoPState
			self.grantScopes = grantScopes
			self.tokenState = tokenState
		}

		public struct TokenState: Codable, Sendable {
			var grantExpiry: Date?
			var accessToken: AccessToken
			var refreshToken: RefreshToken?

			// User authorized scopes
			var scopes: [String]

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
		let clientId: String
		let dPopKey: OAuth.DPoP.Key?
		let issuingServer: String

		public let additionalParams: [String: String]?
		//stores the authorization grant scope:
		public let grantScopes: [String]?
		public var clientAuth: Data?
		public var tokenState: TokenState

		public init(
			clientId: String,
			dPopKey: OAuth.DPoP.Key?,
			issuingServer: String,
			additionalParams: [String: String]?,
			grantScopes: [String]?,
			tokenState: TokenState
		) {
			self.clientId = clientId
			self.dPopKey = dPopKey
			self.issuingServer = issuingServer
			self.additionalParams = additionalParams
			self.grantScopes = grantScopes
			self.tokenState = tokenState
		}

		public struct Mutable: Codable, Sendable {
			public let clientAuth: Data?
			public let tokenState: TokenState

			public init(
				clientAuth: Data?,
				tokenState: TokenState
			) {
				self.clientAuth = clientAuth
				self.tokenState = tokenState
			}
		}

		public mutating func merge(mutable: Mutable) {
			clientAuth = mutable.clientAuth
			tokenState = mutable.tokenState
		}
	}

	public convenience init(
		archive: Archive,
		dpopDecoder: OAuth.DPoP.NonceDecoder?
	) throws {
		self.init(
			clientId: archive.clientId,
			issuingServer: archive.issuingServer,
			additionalParams: archive.additionalParams,
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
				additionalParams: additionalParams,
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
		public let issuingServer: String?
		//stores the additional parameters from the TokenResponse
		public let additionalParams: [String: String]?
		//stores the authorization grant scope:
		public let grantScopes: [String]?

		public init(
			issuingServer: String? = nil,
			additionalParams: [String: String]? = nil,
			grantScopes: [String]?
		) {
			self.issuingServer = issuingServer
			self.additionalParams = additionalParams
			self.grantScopes = grantScopes
		}
	}
}

extension OAuth.SessionState.Archive {
	static public func mock() -> Self {
		.init(
			clientId: "app.example.com",
			dPopKey: .generateP256(),
			issuingServer: "ussure.example.com",
			additionalParams: nil,
			grantScopes: nil,
			tokenState: .mock()
		)
	}
}

extension OAuth.SessionState.TokenState {
	//takes the place of a public memberwise intializer
	static public func mock(
		accessToken: OAuth.AccessToken = .mock(),
		refreshToken: OAuth.RefreshToken? = nil,
		scopes: [String] = [],
		grantExpiresIn: TimeInterval? = nil
	) -> Self {
		.init(
			accessToken: accessToken,
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
	) -> Self {
		.init(value: value, expiresIn: expiresIn)
	}
}

extension OAuth.RefreshToken {
	static public func mock(
		value: String = UUID().uuidString,
		expiresIn: TimeInterval? = nil
	) -> Self {
		.init(value: value, expiresIn: expiresIn)
	}
}
