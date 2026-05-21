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
///Client defined paramenters for requests to the Auth server, for refresh and user auth requests.
///does not include the issuer so that it can be lazily fetched

extension OAuth {
	public protocol TokenRefreshOptions: Sendable {
		var additionalParameters: [String: String] { get }

		func validate(
			tokenResponse: TokenEndpointResponse,
			authServerMetadata: AuthServerMetadata,
			previousState: SessionState.Snapshot?
		) async throws -> Bool
	}

	public protocol TokenAuthorizeOptions: Sendable {
		associatedtype ValidationOutput: Sendable
		var additionalParameters: [String: String] { get }
		
		func validate(
			tokenResponse: TokenEndpointResponse,
			authServerMetadata: AuthServerMetadata,
		) async throws -> ValidationOutput
	}
}

