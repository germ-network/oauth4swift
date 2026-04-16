//
//  SessionCapabilities.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26.
//

import Crypto
import Foundation
import GermConvenience

extension OAuth {
	public protocol SessionCapabilities: Actor, ClientAuthenticatable {
		nonisolated var clientId: String { get }

		var lazyServerMetadata: LazyResource<AuthServerMetadata> { get }

		var session: SessionState { get throws }
		func refreshed(tokenState: SessionState.TokenState) throws
		var refreshTask: Task<SessionState.TokenState, Error>? { get set }

		//auth
		var retriableIssuer: URL { get async throws }
		var authServerRequestOptions: AuthServerRequestOptions { get }
	}
}
