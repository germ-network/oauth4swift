//
//  Authorize.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/8/26.
//

import Foundation
import GermConvenience
import HTTPTypes
import Logging

//for authorize
public struct AuthorizeInputs {
	let clientMetadata: OAuthClient
	let clientAuthentication: any OAuthClientAuthenticatable
	let requestedScopes: [String]
	let pkceVerifier: PKCEVerifier
	let parameters: FormParameters?
	let issuer: URL
	var stateToken: String?

	public init(
		clientMetadata: OAuthClient,
		clientAuthentication: any OAuthClientAuthenticatable,
		scopes: [String]? = nil,
		stateToken: String?,
		pkceVerifier: PKCEVerifier = .init(),
		parameters: FormParameters?,
		issuer: URL
	) {
		self.clientMetadata = clientMetadata
		self.clientAuthentication = clientAuthentication
		self.stateToken = stateToken
		self.pkceVerifier = pkceVerifier
		self.parameters = parameters
		self.issuer = issuer

		if let scopes {
			self.requestedScopes = scopes
		} else {
			self.requestedScopes = clientMetadata.scopes
		}
	}
}
