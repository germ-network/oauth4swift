//
//  TokenEndpointResponse.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/5/26.
//

import Foundation

public struct TokenEndpointResponse {
	public let accessToken: String
	public let expiresIn: Int?
	//	let idToken: String?
	public let refreshToken: String?
	public let scope: String?
	//	let authorizationDetails:
	public let tokenType: TokenType

	//capture additional fields
	public let additionalFields: [String: Any]?

	//TODO: allow extension for unknown types
	//example in oauth4web: RecognizedTokenTypes
	//https://github.com/panva/oauth4webapi/blob/aa0de3f77edab0f0d2b1e1f8ddf875de4f72e8e6/src/index.ts#L3211
	public enum TokenType: String, Decodable {
		case bearer
		case dpop

		init(string: String) throws {
			switch string.lowercased() {
			case TokenType.dpop.rawValue:
				self = .dpop
			case TokenType.bearer.rawValue:
				self = .bearer
			default:
				throw OAuthError.unrecognizedTokenType
			}
		}
	}
}
extension TokenEndpointResponse: Decodable {
	enum CodingKeys: String, CodingKey {
		case accessToken = "access_token"
		case expiresIn = "expires_in"
		//		case idToken = "id_token"
		case refreshToken = "refresh_token"
		case scope
		case tokenType = "token_type"
	}

	public init(from decoder: Decoder) throws {
		// 1. Decode standard keys
		let container = try decoder.container(keyedBy: CodingKeys.self)
		accessToken = try container.decode(String.self, forKey: .accessToken)
		expiresIn = try container.decodeIfPresent(Int.self, forKey: .expiresIn)
		//		idToken = try container.decodeIfPresent(String.self, forKey: .idToken)
		refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
		scope = try container.decodeIfPresent(String.self, forKey: .scope)
		let tokenString = try container.decode(String.self, forKey: .tokenType)
		tokenType = try .init(string: tokenString)

		// 2. Capture everything else
		let extraContainer = try decoder.container(keyedBy: DynamicCodingKeys.self)
		var tempExtraFields = [String: Any]()

		for key in extraContainer.allKeys {
			// Skip keys already decoded
			if CodingKeys(rawValue: key.stringValue) == nil {
				// Decode value as a generic type (requires flexibility)
				if let value = try? extraContainer.decode(String.self, forKey: key)
				{
					tempExtraFields[key.stringValue] = value
				} else if let value = try? extraContainer.decode(
					Int.self, forKey: key)
				{
					tempExtraFields[key.stringValue] = value
				}
				// Add more types as needed
			}
		}
		self.additionalFields = tempExtraFields
	}

	struct DynamicCodingKeys: CodingKey {
		var stringValue: String
		init?(stringValue: String) { self.stringValue = stringValue }
		var intValue: Int?
		init?(intValue: Int) { return nil }
	}
}
