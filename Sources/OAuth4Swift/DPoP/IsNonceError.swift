//
//  IsNonceError.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 4/21/26.
//

import Foundation
import GermConvenience

extension OAuth.DPoP {
	enum Endpoint {
		case auth
		case resource

		func isDPoPNonceError(bundledResponse: HTTPDataResponse) -> Bool {
			switch self {
			// logic matching
			//https://github.com/bluesky-social/atproto/blob/4e96e2c7/packages/oauth/oauth-client/src/fetch-dpop.ts#L
			case .auth:
				guard bundledResponse.response.status == .badRequest else {
					return false
				}
				do {
					let err = try JSONDecoder().decode(
						OAuth.ErrorResponse.self, from: bundledResponse.data
					)
					return err.error == "use_dpop_nonce"
				} catch {
					return false
				}
			//https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid
			case .resource:
				guard bundledResponse.response.status == .unauthorized else {
					return false
				}

				if let wwwAuthHeader = bundledResponse.response.headerFields[
					.wwwAuthenticate]
				{
					if wwwAuthHeader.starts(with: "DPoP") {
						return wwwAuthHeader.contains(
							"error=\"use_dpop_nonce\"")
					}
				}

			}
			return false
		}
	}
}
