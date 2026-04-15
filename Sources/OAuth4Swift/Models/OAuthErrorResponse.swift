//
//  OAuthErrorResponse.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/24/26.
//

import Foundation

/// Decodes a OAuth Error Response, as specified in
/// https://www.rfc-editor.org/rfc/rfc9126.html#name-error-response
/// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
/// https://github.com/germ-network/AtprotoOAuth/pull/9
public struct OAuthErrorResponse: Codable, Hashable, Sendable {
	public let error: String
	public let errorDescription: String?
	public let errorURI: URL?

	enum CodingKeys: String, CodingKey {
		case error
		case errorDescription = "error_description"
		case errorURI = "error_uri"
	}

	//	public enum ErrorCodes: String, Sendable, Codable {
	//		case unauthorizedClient = "unauthorized_client"
	//		case accessDenied = "access_denied"
	//		case unsupportedResponseType = "unsupported_response_type"
	//		case invalid_scope = "invalid_scope"
	//		case serverError = "server_error"
	//		case temporarilyUnavailable = "temporarily_unavailable"
	//	}
}

/// Additional common OAuth responses can be included here later.
/// For example OAuthTokenResponse or similar.
