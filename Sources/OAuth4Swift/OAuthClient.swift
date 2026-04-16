//
//  OAuthClient.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation

extension OAuth {
	public struct Client: Codable, Hashable, Sendable {
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
				try redirectURI.scheme.tryUnwrap
			}
		}
	}
}
