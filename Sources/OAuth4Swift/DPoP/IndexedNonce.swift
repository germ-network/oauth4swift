//
//  NonceValue.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/24/26.
//

import Foundation
import GermConvenience

public typealias NonceDecoder = (HTTPDataResponse) throws -> IndexedNonce?

//NSCache requires class values
public final class IndexedNonce {
	public let origin: String
	public let nonce: String

	public convenience init(
		requestUrl: URL,
		nonce: String
	) throws {
		self.init(
			origin: try requestUrl.origin,
			nonce: nonce
		)
	}

	init(origin: String, nonce: String) {
		self.origin = origin
		self.nonce = nonce
	}
}
