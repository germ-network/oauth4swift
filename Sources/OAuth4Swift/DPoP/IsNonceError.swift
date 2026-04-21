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
			case .auth:
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
			//https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid
			case .resource:
				do {
					let err = try JSONDecoder().decode(
						OAuth.ErrorResponse.self, from: bundledResponse.data
					)
					return err.error == "use_dpop_nonce"
				} catch {
					return false
				}
			}
			return false
		}
	}
}
