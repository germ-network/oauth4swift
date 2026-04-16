//
//  SessionState.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation

public protocol OAuthToken: Codable, Hashable, Sendable {
	var expiry: Date? { get }
}

extension OAuthToken {
	public var valid: Bool {
		guard let date = expiry else { return true }

		return date.timeIntervalSinceNow > 0
	}
}

public struct AccessToken: OAuthToken {
	public let value: String
	public let expiry: Date?

	public init(value: String, expiresIn seconds: Int?) {
		self.value = value
		if let seconds {
			self.expiry = Date(timeIntervalSinceNow: TimeInterval(seconds))
		} else {
			self.expiry = nil
		}
	}
}

/// Holds a refresh token value and optionally it's expiry
public struct RefreshToken: OAuthToken {
	public let value: String
	public let expiry: Date?

	public init?(value: String?, timeout seconds: Int?) {
		guard let value else {
			return nil
		}

		self.value = value
		if let seconds {
			self.expiry = Date(timeIntervalSinceNow: TimeInterval(seconds))
		} else {
			self.expiry = nil
		}
	}
}

//best way to express fixed key and variable accessToken is as a reference type
extension OAuth {
	public class SessionState {
		public let clientId: String
		public let issuingServer: String?
		//stores the additional parameters from the TokenResponse
		public let additionalParams: [String: String]?
		//not mandatory in OAuth 2.1
		public let dPopKey: DPoPKey?
		//stores the authorization grant scope:
		public let grantScopes: [String]?
		
		//mutable state
		let authComponent: any OAuth.ClientAuthComponent
		var tokenState: TokenState
		
		public init(
			clientId: String,
			dPopKey: DPoPKey?,
			issuingServer: String? = nil,
			additionalParams: [String: String]? = nil,
			grantScopes: [String]?,
			authComponent: some OAuth.ClientAuthComponent,
			tokenState: TokenState
		) {
			self.clientId = clientId
			self.dPopKey = dPopKey
			self.issuingServer = issuingServer
			self.additionalParams = additionalParams
			self.grantScopes = grantScopes
			self.authComponent = authComponent
			self.tokenState = tokenState
		}
		
		public struct TokenState: Codable, Sendable {
			var grantExpiry: Date?
			var accessToken: AccessToken
			var refreshToken: RefreshToken?
			
			// User authorized scopes
			var scopes: [String]
			
			public init(
				accessToken: AccessToken,
				refreshToken: RefreshToken? = nil,
				scopes: [String] = [],
				grantExpiresIn seconds: Int? = nil
			) {
				self.accessToken = accessToken
				self.refreshToken = refreshToken
				self.scopes = scopes
				
				// Support for Authorization Grants with expiry:
				// https://www.ietf.org/archive/id/draft-ietf-oauth-refresh-token-expiration-01.html
				if let seconds {
					self.grantExpiry = Date(timeIntervalSinceNow: TimeInterval(seconds))
				} else {
					self.grantExpiry = nil
				}
			}
			
			/// Determines if the token object is valid.
			///
			/// A token without an expiry is unconditionally valid.
			public var valid: Bool {
				guard let date = grantExpiry else { return true }
				
				return date.timeIntervalSinceNow > 0
			}
		}
	}
}

extension OAuth.SessionState {
	public struct Archive: Sendable, Codable {
		let clientId: String
		let clientAuthMethod: OAuth.TokenEndpointMethods
		let dPopKey: DPoPKey?
		let issuingServer: String?

		public let additionalParams: [String: String]?
		//stores the authorization grant scope:
		public let grantScopes: [String]?
		public let clientAuth: Data?
		public let tokenState: OAuth.SessionState.TokenState

		public init(
			clientId: String,
			clientAuthMethod: OAuth.TokenEndpointMethods,
			dPopKey: DPoPKey?,
			issuingServer: String?,
			additionalParams: [String: String]?,
			grantScopes: [String]?,
			clientAuth: Data?,
			tokenState: OAuth.SessionState.TokenState
		) {
			self.clientId = clientId
			self.clientAuthMethod = clientAuthMethod
			self.dPopKey = dPopKey
			self.issuingServer = issuingServer
			self.additionalParams = additionalParams
			self.grantScopes = grantScopes
			self.clientAuth = clientAuth
			self.tokenState = tokenState
		}

		//		public func merge(update: SessionState.Mutable) -> Self {
		//			.init(
		//				clientId: clientId,
		//				clientAuthMethod: clientAuthMethod,
		//				dPopKey: dPopKey,
		//				issuingServer: issuingServer,
		//				additionalParams: additionalParams,
		//				grantScopes: grantScopes,
		//				mutable: update
		//			)
		//		}
	}

	public convenience init(
		archive: Archive,
		clientAuthFactory: OAuth.ClientAuthComponentFactory = OAuth
			.DefaultClientAuthComponentFactory
	) throws {
		self.init(
			clientId: archive.clientId,
			dPopKey: archive.dPopKey,
			issuingServer: archive.issuingServer,
			additionalParams: archive.additionalParams,
			grantScopes: archive.grantScopes,
			authComponent: try clientAuthFactory(
				archive.clientAuthMethod,
				archive
					.clientAuth),
			tokenState: archive.tokenState
		)
	}

	public var archive: Archive {
		get throws {
			.init(
				clientId: clientId,
				clientAuthMethod: authComponent.tokenEndpointAuthMethod,
				dPopKey: dPopKey,
				issuingServer: issuingServer,
				additionalParams: additionalParams,
				grantScopes: grantScopes,
				clientAuth: try authComponent.archive,
				tokenState: tokenState
			)
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
