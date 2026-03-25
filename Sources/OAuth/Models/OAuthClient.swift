//
//  OAuthClient.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation

// The OAuthClient is primarily the client_id
public struct OAuthClient: Codable, Hashable, Sendable {
	public let clientId: String

	//should be a subset of the scopes our client actually has:
	public let scopes: [String]
	public let redirectURI: URL

	public init(clientId: String, scopes: [String], redirectURI: URL) {
		self.clientId = clientId
		self.scopes = scopes
		self.redirectURI = redirectURI
	}

	var redirectURIScheme: String {
		get throws {
			guard let scheme = redirectURI.scheme else {
				throw OAuthError.missingScheme
			}
			return scheme
		}
	}
}
