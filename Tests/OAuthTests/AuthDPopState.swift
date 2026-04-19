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
public actor IsolatedDPopState: OAuth.DPoP.Signing {
	let state: OAuth.DPoP.State

	public var dpopKey: OAuth.DPoP.Key {
		state.signingKey
	}

	public init(
		dpopKey: OAuth.DPoP.Key,
		decoder: @escaping OAuth.DPoP.NonceDecoder
	) {
		self.state = .init(signingKey: dpopKey, decoder: decoder)
	}

	public func getNonce(origin: String) -> OAuth.DPoP.IndexedNonce? {
		state.getNonce(origin: origin)
	}

	public func cacheNonce(response: HTTPDataResponse, requestUrl: URL) throws {
		try state.cacheNonce(response: response, requestUrl: requestUrl)
	}
}
