//
//  PKCEVerifier.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Crypto
import Foundation

public struct PKCEVerifier: Sendable {
	public struct Challenge: Hashable, Sendable {
		public let value: String
		public let method: String
	}
	public typealias HashFunction = @Sendable (String) -> String

	public let verifier: String
	public let challenge: Challenge
	public let hashFunction: HashFunction

	public static func randomString(length: Int) -> String {
		let characters = Array(
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

		var string = ""

		for _ in 0..<length {
			string.append(characters.randomElement()!)
		}

		return string
	}

	public init(hash: String, hasher: @escaping HashFunction) {
		self.verifier = PKCEVerifier.randomString(length: 64)
		self.hashFunction = hasher

		self.challenge = Challenge(
			value: hashFunction(verifier),
			method: hash
		)
	}
}

extension SHA256.Digest {
	var data: Data {
		self.withUnsafeBytes { buffer in
			Data(bytes: buffer.baseAddress!, count: buffer.count)
		}
	}
}

extension PKCEVerifier {
	public init() {
		self.init(
			hash: "S256",
			hasher: { value in
				SHA256.hash(data: value.utf8Data)
					.data.base64URLEncodedString()
			}
		)
	}
}
