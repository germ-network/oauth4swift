//
//  ClientMetadata.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation

// A subset of the Client Identifier Metadata Document contents:
public struct ClientMetadata: Codable, Hashable, Sendable {
	public let clientId: String

	//should be a subset of the scopes in our client identifier metadata document:
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
