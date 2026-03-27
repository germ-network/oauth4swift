//
//  SessionState.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation

public struct AccessToken: Codable, Hashable, Sendable {
	public let value: String
	public let expiry: Date?

	public init(value: String, expiry: Date? = nil) {
		self.value = value
		self.expiry = expiry
	}

	public init(value: String, expiresIn seconds: Int?) {
		self.value = value
		if let seconds {
			self.expiry = Date(timeIntervalSinceNow: TimeInterval(seconds))
		} else {
			self.expiry = nil
		}
	}

	/// Determines if the token object is valid.
	///
	/// A token without an expiry is unconditionally valid.
	public var valid: Bool {
		guard let date = expiry else { return true }

		return date.timeIntervalSinceNow > 0
	}
}

/// Holds a refresh token value and optionally it's expiry
public struct RefreshToken: Codable, Hashable, Sendable {
	public let value: String
	public let expiry: Date?

	public init?(refreshToken: String?, timeout seconds: Int?) {
		guard let refreshToken else {
			return nil
		}

		self.value = refreshToken
		if let seconds {
			self.expiry = Date(timeIntervalSinceNow: TimeInterval(seconds))
		} else {
			self.expiry = nil
		}
	}

	/// Determines if the token object is valid.
	///
	/// A token without an expiry is unconditionally valid.
	public var valid: Bool {
		guard let date = expiry else { return true }

		return date.timeIntervalSinceNow > 0
	}
}

//best way to express fixed key and variable accessToken is as a reference type
public class SessionState {
	public let client: OAuthClient
	public let issuingServer: String?
	//stores the additional parameters from the TokenResponse
	public let additionalParams: [String: String]?
	//not mandatory in OAuth 2.1
	public let dPopKey: DPoPKey?
	//stores the authorization grant scope:
	public let grantScopes: [String]?

	var mutable: Mutable

	public init(
		client: OAuthClient,
		dPopKey: DPoPKey?,
		issuingServer: String? = nil,
		additionalParams: [String: String]? = nil,
		grantScopes: [String]?,
		mutable: Mutable
	) {
		self.client = client
		self.dPopKey = dPopKey
		self.issuingServer = issuingServer
		self.additionalParams = additionalParams
		self.grantScopes = grantScopes
		self.mutable = mutable
	}

	public struct Mutable: Sendable, Codable {
		let grantExpiry: Date?
		let accessToken: AccessToken
		let refreshToken: RefreshToken?

		// User authorized scopes
		let scopes: [String]

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

	public func updated(mutable: Mutable) {
		self.mutable = mutable
	}
}

extension SessionState {
	public struct Archive: Sendable, Codable {
		let client: OAuthClient
		let dPopKey: DPoPKey?
		let issuingServer: String?

		public let additionalParams: [String: String]?
		//stores the authorization grant scope:
		public let grantScopes: [String]?
		public let mutable: SessionState.Mutable

		public init(
			client: OAuthClient,
			dPopKey: DPoPKey?,
			issuingServer: String?,
			additionalParams: [String: String]?,
			grantScopes: [String]?,
			mutable: SessionState.Mutable
		) {
			self.client = client
			self.dPopKey = dPopKey
			self.issuingServer = issuingServer
			self.additionalParams = additionalParams
			self.grantScopes = grantScopes
			self.mutable = mutable
		}

		public func merge(update: SessionState.Mutable) -> Self {
			.init(
				client: client,
				dPopKey: dPopKey,
				issuingServer: issuingServer,
				additionalParams: additionalParams,
				grantScopes: grantScopes,
				mutable: update
			)
		}
	}

	public convenience init(archive: Archive) {
		self.init(
			client: archive.client,
			dPopKey: archive.dPopKey,
			issuingServer: archive.issuingServer,
			additionalParams: archive.additionalParams,
			grantScopes: archive.grantScopes,
			mutable: archive.mutable
		)
	}

	public var archive: Archive {
		.init(
			client: client,
			dPopKey: dPopKey,
			issuingServer: issuingServer,
			additionalParams: additionalParams,
			grantScopes: grantScopes,
			mutable: mutable
		)
	}
}

public class ImmutableSessionState {
	public let client: OAuthClient
	public let issuingServer: String?
	//stores the additional parameters from the TokenResponse
	public let additionalParams: [String: String]?
	//stores the authorization grant scope:
	public let grantScopes: [String]?

	public init(
		client: OAuthClient,
		issuingServer: String? = nil,
		additionalParams: [String: String]? = nil,
		grantScopes: [String]?
	) {
		self.client = client
		self.issuingServer = issuingServer
		self.additionalParams = additionalParams
		self.grantScopes = grantScopes
	}

	static func fromSessionState(_ state: SessionState) -> ImmutableSessionState {
		.init(
			client: state.client,
			issuingServer: state.issuingServer,
			additionalParams: state.additionalParams,
			grantScopes: state.grantScopes
		)
	}
}
