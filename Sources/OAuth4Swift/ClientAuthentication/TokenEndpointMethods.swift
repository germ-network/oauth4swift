//
//  TokenEndpointMethods.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 4/15/26.
//

import Foundation

///https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xml#token-endpoint-auth-method
extension OAuth {
	public enum TokenEndpointMethods: String, Codable, Sendable {
		case none
		case clientSecretPost = "client_secret_post"
		case clientSecretBasic = "client_secret_basic"
		case clientSecretJwt = "client_secret_jwt"
		case privateKeyJwt = "private_key_jwt"
		case tlsClientAuth = "tls_client_auth"
		case selfSignedTlsClientAuth = "self_signed_tls_client_auth"
	}
}
