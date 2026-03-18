//
//  AuthorizationServer.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/4/26.
//

import Foundation
import GermConvenience

// See: https://www.rfc-editor.org/rfc/rfc8414.html
public struct AuthServerMetadata: Codable, Hashable, Sendable {
	/// The authorization server's issuer identifier
	public let issuer: String

	/// Array of claim types supported
	let claimsSupported: [String]?

	/// Languages and scripts supported for claims
	let claimsLocalesSupported: [String]?

	/// Whether the claims parameter is supported
	let claimsParameterSupported: Bool?

	/// Whether the request parameter is supported
	let requestParameterSupported: Bool?

	/// Whether the request_uri parameter is supported
	let requestUriParameterSupported: Bool?

	/// Whether request_uri values must be pre-registered
	let requireRequestUriRegistration: Bool?

	/// Array of OAuth 2.0 scope values supported
	let scopesSupported: [String]?

	/// Subject identifier types supported
	let subjectTypesSupported: [String]?

	/// Response types supported
	let responseTypesSupported: [String]?

	/// Response modes supported
	let responseModesSupported: [String]?

	/// Grant types supported
	let grantTypesSupported: [String]?

	/// PKCE code challenge methods supported
	let codeChallengeMethodsSupported: [String]?

	/// Languages and scripts supported for UI
	let uiLocalesSupported: [String]?

	/// Algorithms supported for signing ID tokens
	let idTokenSigningAlgValuesSupported: [String]?

	/// Display values supported
	let displayValuesSupported: [String]?

	/// Prompt values supported
	let promptValuesSupported: [String]?

	/// Algorithms supported for signing request objects
	let requestObjectSigningAlgValuesSupported: [String]?

	/// Whether authorization response issuer parameter is supported
	let authorizationResponseIssParameterSupported: Bool?

	/// Authorization details types supported
	let authorizationDetailsTypesSupported: [String]?

	/// Algorithms supported for encrypting request objects
	let requestObjectEncryptionAlgValuesSupported: [String]?

	/// Encryption encodings supported for request objects
	let requestObjectEncryptionEncValuesSupported: [String]?

	/// URL of the authorization server's JWK Set document
	let jwksUri: URL?

	/// URL of the authorization endpoint
	let authorizationEndpoint: URL

	/// URL of the token endpoint
	let tokenEndpoint: URL

	/// Authentication methods supported at token endpoint (RFC 8414 Section 2)
	let tokenEndpointAuthMethodsSupported: [String]?

	/// Signing algorithms supported for token endpoint authentication
	let tokenEndpointAuthSigningAlgValuesSupported: [String]?

	/// URL of the revocation endpoint
	let revocationEndpoint: URL?

	/// Authentication methods supported at revocation endpoint
	let revocationEndpointAuthMethodsSupported: [String]?

	/// Signing algorithms supported for revocation endpoint authentication
	let revocationEndpointAuthSigningAlgValuesSupported: [String]?

	/// URL of the introspection endpoint
	let introspectionEndpoint: URL?

	/// Authentication methods supported at introspection endpoint
	let introspectionEndpointAuthMethodsSupported: [String]?

	/// Signing algorithms supported for introspection endpoint authentication
	let introspectionEndpointAuthSigningAlgValuesSupported: [String]?

	/// URL of the pushed authorization request endpoint
	let pushedAuthorizationRequestEndpoint: URL?

	/// Authentication methods supported at PAR endpoint
	let pushedAuthorizationRequestEndpointAuthMethodsSupported: [String]?

	/// Signing algorithms supported for PAR endpoint authentication
	let pushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported: [String]?

	/// Whether pushed authorization requests are required
	let requirePushedAuthorizationRequests: Bool?

	/// URL of the UserInfo endpoint
	let userinfoEndpoint: URL?

	/// URL of the end session endpoint
	let endSessionEndpoint: URL?

	/// URL of the dynamic client registration endpoint
	let registrationEndpoint: URL?

	/// DPoP signing algorithms supported (RFC 9449 Section 5.1)
	let dpopSigningAlgValuesSupported: [String]?

	/// Protected resource URIs (RFC 9728 Section 4)
	let protectedResources: [URL]?

	/// Whether client ID metadata document is supported
	let clientIdMetadataDocumentSupported: Bool?

	enum CodingKeys: String, CodingKey {
		case issuer
		case claimsSupported = "claims_supported"
		case claimsLocalesSupported = "claims_locales_supported"
		case claimsParameterSupported = "claims_parameter_supported"
		case requestParameterSupported = "request_parameter_supported"
		case requestUriParameterSupported = "request_uri_parameter_supported"
		case requireRequestUriRegistration = "require_request_uri_registration"
		case authorizationEndpoint = "authorization_endpoint"
		case tokenEndpoint = "token_endpoint"
		case responseTypesSupported = "response_types_supported"
		case grantTypesSupported = "grant_types_supported"
		case codeChallengeMethodsSupported = "code_challenge_methods_supported"
		case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
		case tokenEndpointAuthSigningAlgValuesSupported =
			"token_endpoint_auth_signing_alg_values_supported"
		case scopesSupported = "scopes_supported"
		case authorizationResponseIssParameterSupported =
			"authorization_response_iss_parameter_supported"
		case requirePushedAuthorizationRequests = "require_pushed_authorization_requests"
		case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
		case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
		case clientIdMetadataDocumentSupported = "client_id_metadata_document_supported"

		case responseModesSupported = "response_modes_supported"
		case subjectTypesSupported = "subject_types_supported"
		case uiLocalesSupported = "ui_locales_supported"
		case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
		case displayValuesSupported = "display_values_supported"
		case promptValuesSupported = "prompt_values_supported"
		case requestObjectSigningAlgValuesSupported =
			"request_object_signing_alg_values_supported"
		case authorizationDetailsTypesSupported = "authorization_details_types_supported"
		case requestObjectEncryptionAlgValuesSupported =
			"request_object_encryption_alg_values_supported"
		case requestObjectEncryptionEncValuesSupported =
			"request_object_encryption_enc_values_supported"
		case jwksUri = "jwks_uri"
		case revocationEndpoint = "revocation_endpoint"
		case revocationEndpointAuthMethodsSupported =
			"revocation_endpoint_auth_methods_supported"
		case revocationEndpointAuthSigningAlgValuesSupported =
			"revocation_endpoint_auth_signing_alg_values_supported"
		case introspectionEndpoint = "introspection_endpoint"
		case introspectionEndpointAuthMethodsSupported =
			"introspection_endpoint_auth_methods_supported"
		case introspectionEndpointAuthSigningAlgValuesSupported =
			"introspection_endpoint_auth_signing_alg_values_supported"
		case pushedAuthorizationRequestEndpointAuthMethodsSupported =
			"pushed_authorization_request_endpoint_auth_methods_supported"
		case pushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported =
			"pushed_authorization_request_endpoint_auth_signing_alg_values_supported"
		case userinfoEndpoint = "userinfo_endpoint"
		case endSessionEndpoint = "end_session_endpoint"
		case registrationEndpoint = "registration_endpoint"
		case protectedResources = "protected_resources"
	}

	enum Endpoint {
		case authorization
		case token
		case par
	}

	//for our purposes require secure
	func resolve(endpoint: Endpoint) throws -> URL {
		let url: URL =
			switch endpoint {
			case .authorization:
				authorizationEndpoint
			case .token:
				tokenEndpoint
			case .par:
				try pushedAuthorizationRequestEndpoint.tryUnwrap
			}

		guard url.scheme == "https" else {
			throw OAuthError.insecureScheme
		}

		return url
	}
}

extension AuthServerMetadata {
	///from bsky.social
	static public func mock() throws -> Self {
		let data =
			"""
			{"issuer":"https://social.example","request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"scopes_supported":["atproto","transition:email","transition:generic","transition:chat.bsky"],"subject_types_supported":["public"],"response_types_supported":["code"],"response_modes_supported":["query","fragment","form_post"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"ui_locales_supported":["en-US"],"display_values_supported":["page","popup","touch"],"request_object_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512","none"],"authorization_response_iss_parameter_supported":true,"request_object_encryption_alg_values_supported":[],"request_object_encryption_enc_values_supported":[],"jwks_uri":"https://social.example/oauth/jwks","authorization_endpoint":"https://social.example/oauth/authorize","token_endpoint":"https://social.example/oauth/token","token_endpoint_auth_methods_supported":["none","private_key_jwt"],"token_endpoint_auth_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],"revocation_endpoint":"https://social.example/oauth/revoke","pushed_authorization_request_endpoint":"https://social.example/oauth/par","require_pushed_authorization_requests":true,"dpop_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],"client_id_metadata_document_supported":true}
			""".utf8Data

		return try JSONDecoder().decode(AuthServerMetadata.self, from: data)
	}
}
