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
		public let clientInfo: OAuth.ClientInfo
		let pkceVerifier: PKCEVerifier
		let issuer: URL
		let inputToken: String?
		
		public init(
			clientInfo: ClientInfo,
			pkceVerifier: PKCEVerifier = .init(),
			issuer: URL,
			inputToken: String?,
		) {
			self.clientInfo = clientInfo
			self.pkceVerifier = pkceVerifier
			self.issuer = issuer
			self.inputToken = inputToken
		}
	}
}
