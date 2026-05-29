//
//  TokenOptions.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/8/26.
//

import Foundation
import GermConvenience
import Logging

///Shared code among the initial auth flow and subsequent refresh
///Client defined parameters for requests to the Auth server for authorization requests, token exchanges and for refresh requests.
///does not include the issuer so that it can be lazily fetched

extension OAuth {
	public protocol TokenRefreshOptions: Sendable {
		var additionalTokenRequestParameters: FormParameters? { get }

		///Should return false if the tokenResponse is invalid, and throw if it is unable to
		///resolve the validity - e.g. if an onlne check is required and the client is currently offline
		func validate(
			tokenResponse: TokenEndpointResponse,
			authServerMetadata: AuthServerMetadata,
			previousState: SessionState.Snapshot
		) async throws -> Bool
	}

	public protocol TokenAuthorizeOptions: Sendable {
		associatedtype ValidationOutput: Sendable
		var additionalTokenRequestParameters: FormParameters? { get }

		///In contrast to the above, if the TokenEndpointResponse is invalid, this method should throw
		///OAuth.Errors.tokenInvalid
		func validate(
			tokenResponse: TokenEndpointResponse,
			authServerMetadata: AuthServerMetadata,
		) async throws -> ValidationOutput
	}
}

//default additionalParameters to empty
extension OAuth.TokenRefreshOptions {
	public var additionalTokenRequestParameters: FormParameters? { nil }
}

extension OAuth.TokenAuthorizeOptions {
	public var additionalTokenRequestParameters: FormParameters? { nil }
}
