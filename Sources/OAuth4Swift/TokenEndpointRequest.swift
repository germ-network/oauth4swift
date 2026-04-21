//
//  TokenEndpointRequest.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/4/26.
//

import Foundation
import GermConvenience

extension OAuth {
	enum GrantType: String {
		case authorizationCode = "authorization_code"
		case refreshToken = "refresh_token"
		case clientCredentials = "client_credentials"
	}
}
