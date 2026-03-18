//
//  SessionState.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation

/// Holds an access token value and its expiry.
public struct Token: Codable, Hashable, Sendable {
	/// The access token.
	public let value: String

	/// An optional expiry.
	public let expiry: Date?

	public init?(refreshToken: String?) {
		guard let refreshToken else {
			return nil
		}
		self.value = refreshToken
		self.expiry = nil
	}
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

//best way to express fixed key and variable accessToken is as a reference type
public class SessionState {
	//not mandatory in OAuth 2.1
	public let dPopKey: DPoPKey?

	public let additionalParams: [String: String]?

	var mutable: Mutable

	public init(
		dPopKey: DPoPKey?,
		additionalParams: [String: String]? = nil,
		mutable: Mutable
	) {
		self.dPopKey = dPopKey
		self.additionalParams = additionalParams
		self.mutable = mutable
	}

	public convenience init(
		accessToken: String,
		validUntilDate: Date? = nil,
		dPopKey: DPoPKey?
	) {
		self.init(
			dPopKey: dPopKey,
			mutable: .init(
				accessToken: .init(value: accessToken, expiry: validUntilDate)
			)
		)
	}

	//periphery: ignore
	//codable properties
	public struct Mutable: Sendable, Codable {
		let accessToken: Token
		public let refreshToken: Token?

		// User authorized scopes
		let scopes: [String]
		let issuingServer: String?

		public init(
			accessToken: Token,
			refreshToken: Token? = nil,
			scopes: [String] = [],
			issuingServer: String? = nil
		) {
			self.accessToken = accessToken
			self.refreshToken = refreshToken
			self.scopes = scopes
			self.issuingServer = issuingServer
		}
	}

	public func updated(mutable: Mutable) {
		self.mutable = mutable
	}
}

extension SessionState {
	public struct Archive: Sendable, Codable {
		let dPopKey: DPoPKey?

		public let additionalParams: [String: String]?

		public let mutable: SessionState.Mutable

		public init(
			dPopKey: DPoPKey?,
			additionalParams: [String: String]?,
			mutable: SessionState.Mutable
		) {
			self.dPopKey = dPopKey
			self.additionalParams = additionalParams
			self.mutable = mutable
		}

		public func merge(update: SessionState.Mutable) -> Self {
			.init(
				dPopKey: dPopKey,
				additionalParams: additionalParams,
				mutable: update
			)
		}
	}

	public convenience init(archive: Archive) {
		self.init(
			dPopKey: archive.dPopKey,
			additionalParams: archive.additionalParams,
			mutable: archive.mutable
		)
	}

	public var archive: Archive {
		.init(
			dPopKey: dPopKey,
			additionalParams: additionalParams,
			mutable: mutable
		)
	}
}
