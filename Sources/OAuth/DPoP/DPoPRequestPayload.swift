//
//  DPoPRequestPayload.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/20/26.
//

import Foundation
import GermConvenience

struct DPoPRequestPayload: Codable, Hashable, Sendable {
	let uniqueCode: String
	let httpMethod: String
	let httpRequestURL: String
	/// UNIX type, seconds since epoch
	let createdAt: Int
	/// UNIX type, seconds since epoch
	let expiresAt: Int
	let nonce: String?
	let accessTokenHash: String?

	enum CodingKeys: String, CodingKey {
		case uniqueCode = "jti"
		case httpMethod = "htm"
		case httpRequestURL = "htu"
		case createdAt = "iat"
		case expiresAt = "exp"
		case nonce
		case accessTokenHash = "ath"
	}

	init(
		endpointUrl: URL,
		httpMethod: String,
		nonce: String?,
		accessTokenHash: String?
	) throws {
		self.uniqueCode = UUID().uuidString
		self.httpMethod = httpMethod
		self.httpRequestURL = endpointUrl.absoluteString
		self.createdAt = Int(Date.now.timeIntervalSince1970)
		self.expiresAt = Int(Date.now.timeIntervalSince1970 + 3600)
		self.nonce = nonce
		self.accessTokenHash = accessTokenHash
	}
}

enum DPoPError: Error {
	case requestInvalid(URLRequest)
}
