//
//  PARConfiguration.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation

///https://datatracker.ietf.org/doc/html/rfc9126#name-successful-response
public struct PARResponse: Codable, Hashable, Sendable {
	public let requestURI: String
	public let expiresIn: Int

	enum CodingKeys: String, CodingKey {
		case requestURI = "request_uri"
		case expiresIn = "expires_in"
	}
}
