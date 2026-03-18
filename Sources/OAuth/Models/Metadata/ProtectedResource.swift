//
//  ProtectedResource.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/23/26 from OAuthenticator
//

import Foundation
import GermConvenience

// See: https://www.rfc-editor.org/rfc/rfc9728.html
public struct ProtectedResourceMetadata: Codable, Hashable, Sendable {
	public let resource: String
	public let authorizationServers: [String]?
	public let jwksUri: String?
	public let scopesSupported: [String]?
	public let bearerMethodsSupported: [String]?
	public let resourceSigningAlgValuesSupported: [String]?
	public let resourceName: String?
	public let resourceDocumentation: String?
	public let resourcePolicyUri: String?
	public let resourceTosUri: String?
	public let tlsClientCertificateBoundAccessTokens: Bool?
	public let authorizationDetailsTypesSupported: [String]?
	public let dpopSigningAlgValuesSupported: [String]?
	public let dpopBoundAccessTokensRequired: Bool?
	public let signedMetadata: String?

	enum CodingKeys: String, CodingKey {
		case resource
		case authorizationServers = "authorization_servers"
		case jwksUri = "jwks_uri"
		case scopesSupported = "scopes_supported"
		case bearerMethodsSupported = "bearer_methods_supported"
		case resourceSigningAlgValuesSupported = "resource_signing_alg_values_supported"
		case resourceName = "resource_name"
		case resourceDocumentation = "resource_documentation"
		case resourcePolicyUri = "resource_policy_uri"
		case resourceTosUri = "resource_tos_uri"
		case tlsClientCertificateBoundAccessTokens =
			"tls_client_certificate_bound_access_tokens"
		case authorizationDetailsTypesSupported = "authorization_details_types_supported"
		case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
		case dpopBoundAccessTokensRequired = "dpop_bound_access_tokens_required"
		case signedMetadata = "signed_metadata"
	}
}
