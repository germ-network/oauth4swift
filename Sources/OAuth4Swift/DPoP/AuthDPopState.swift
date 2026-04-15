//
//  AuthDPopState.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/9/26.
//

import Foundation
import GermConvenience

///A simple actor to manage dpop state for initial auth

public actor AuthDPopState: DPoPSigning {
	nonisolated public let dpopKey: DPoPKey

	let nonceCache: NSCache<NSString, IndexedNonce> = NSCache()
	private let decoder: (HTTPDataResponse, URL) throws -> IndexedNonce?

	public init(
		dpopKey: DPoPKey,
		decoder: @escaping (HTTPDataResponse, URL) throws -> IndexedNonce?
	) {
		self.dpopKey = dpopKey
		self.decoder = decoder
	}

	public func getNonce(origin: String) -> IndexedNonce? {
		nonceCache.object(forKey: origin as NSString)
	}

	public func cacheNonce(response: HTTPDataResponse, requestUrl: URL) throws {
		let indexedNonce = try decoder(response, requestUrl)
		if let indexedNonce {
			nonceCache.setObject(indexedNonce, forKey: indexedNonce.origin as NSString)
		}
	}

}
