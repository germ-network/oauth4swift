//
//  NegotiateClientAuth.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 4/16/26.
//

import Foundation
import GermConvenience

extension OAuth {
	public protocol Authorizer {
		nonisolated var clientId: String { get }
		
		var authorizeInputs: OAuth.AuthorizeInputs { get }
		var authServerRequestOptions: AuthServerRequestOptions { get }
		var userAuthenticator: UserAuthenticator { get }
		
		func negotiate(authServerMetadata: AuthServerMetadata) throws
		-> ClientAuthenticatable
		
		var authFetcher: HTTPFetcher { get }
	}
}

extension OAuth {
	public struct AuthorizeInputs: Sendable {
		let scopes: [String]
		let redirectURI: URL
		let pkceVerifier: PKCEVerifier
		let issuer: URL
		let inputToken: String?
		
		public init(
			scopes: [String],
			redirectURI: URL,
			pkceVerifier: PKCEVerifier = .init(),
			issuer: URL,
			inputToken: String?,
		) {
			self.scopes = scopes
			self.redirectURI = redirectURI
			self.pkceVerifier = pkceVerifier
			self.issuer = issuer
			self.inputToken = inputToken
		}
	}
}
