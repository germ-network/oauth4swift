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
	var appCredentials: AppCredentials { get }

	var lazyServerMetadata: LazyResource<AuthServerMetadata> { get }

	var session: SessionState { get throws }
	func refreshed(sessionMutable: SessionState.Mutable) throws
	var refreshTask: Task<SessionState.Mutable, Error>? { get set }

	//should follow redirects
	var resourceFetcher: HTTPFetcher { get }

	//auth
	var retriableIssuer: URL { get async throws }

	var authServerRequestOptions: AuthServerRequestOptions { get }
}
