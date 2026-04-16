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

///for authorize only
public struct AuthorizeInputs {
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

///Shared code among the initial auth flow and subsequent refresh
///Client defined paramenters for requests to the Auth server, for refresh and user auth requests.
///does not include the issuer so that it can be lazily \=etched
public struct AuthServerRequestOptions: Sendable {
	public typealias TokenValidator =
		@Sendable (
			TokenEndpointResponse,
			AuthServerMetadata,
			SessionState.Snapshot?
		) async throws -> Bool

	let additionalParameters: [String: String]
	let tokenValidator: TokenValidator

	public init(
		additionalParameters: [String: String],
		tokenValidator: @escaping TokenValidator,
	) {
		self.additionalParameters = additionalParameters
		self.tokenValidator = tokenValidator
	}
}
