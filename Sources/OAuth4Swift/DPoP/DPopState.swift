//
//  DPopState.swift
//  OAuth
//
//  Created by Mark @ Germ on 3/9/26.
//

import Foundation
import GermConvenience

///reusable class to encapsulate DPoP state. Should generally protect this in some isolation (Actor or @MainActor which can conform to DPoPSigning and pass its methods through
///
public class DPopState {
	public let dpopKey: DPoPKey

	public let nonceCache: NSCache<NSString, IndexedNonce> = NSCache()
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
