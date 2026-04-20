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
	//may conform to DPoP.Signing if capable of it
	public protocol SessionCapabilities: Actor, ClientAuth.Authenticable {
		nonisolated var clientId: String { get }

		var lazyServerMetadata: LazyResource<AuthServerMetadata> { get }

		var session: SessionState { get throws }
		func refreshed(tokenState: SessionState.TokenState) throws
		var refreshTask: Task<SessionState.TokenState, Error>? { get set }

		//auth
		var authServerRequestOptions: TokenRequestOptions { get }
	}
}
