//
//  SessionCapabilities.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26.
//

import Crypto
import Foundation
import GermConvenience

public protocol OAuthSessionCapabilities: Actor {
	var clientId: String { get }

	var lazyServerMetadata: LazyResource<AuthServerMetadata> { get }

	var session: SessionState { get throws }
	func refreshed(sessionMutable: SessionState.Mutable) throws
	var refreshTask: Task<SessionState.Mutable, Error>? { get set }

	//should not follow redirects
	var authFetcher: HTTPFetcher { get }

	var authServerRequestOptions: AuthServerRequestOptions { get }
}
