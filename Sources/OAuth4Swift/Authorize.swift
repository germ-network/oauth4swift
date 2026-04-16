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

///Shared code among the initial auth flow and subsequent refresh
///Client defined paramenters for requests to the Auth server, for refresh and user auth requests.
///does not include the issuer so that it can be lazily fetched

extension OAuth {
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
}
