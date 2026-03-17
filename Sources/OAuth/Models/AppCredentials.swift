//
//  AppCredentials.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation

//related to but not equivalent to the ClientMetadata
public struct AppCredentials: Codable, Hashable, Sendable {
	public let clientId: String
	//should be a subset of the scopes in our client metadata
	public let requestedScopes: [String]
	public let callbackURL: URL

	public init(clientId: String, scopes: [String], callbackURL: URL) {
		self.clientId = clientId
		self.requestedScopes = scopes
		self.callbackURL = callbackURL
	}

	var callbackURLScheme: String {
		get throws {
			guard let scheme = callbackURL.scheme else {
				throw OAuthError.missingScheme
			}
			return scheme
		}
	}
}
