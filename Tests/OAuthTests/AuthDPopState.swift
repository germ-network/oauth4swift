//
//  AuthDPopState.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 4/18/26.
//

import Foundation
import GermConvenience
import OAuth4Swift

///A simple actor to manage dpop state for initial auth
public actor IsolatedDPopState: DPoPSigning {
	let state: DPopState

	public var dpopKey: DPoPKey {
		state.dpopKey
	}

	public init(
		dpopKey: DPoPKey,
		decoder: @escaping (HTTPDataResponse, URL) throws -> IndexedNonce?
	) {
		self.state = .init(dpopKey: dpopKey, decoder: decoder)
	}

	public func getNonce(origin: String) -> IndexedNonce? {
		state.getNonce(origin: origin)
	}

	public func cacheNonce(response: HTTPDataResponse, requestUrl: URL) throws {
		try state.cacheNonce(response: response, requestUrl: requestUrl)
	}
}
