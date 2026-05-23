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

		var authServerMetadata: AuthServerMetadata { get async throws }
		var authToken: OAuth.AccessToken { get async throws }

		//lean on the implementation to track state
		//not start multiple refreshes, and save the result
		func startRefresh(
			continueCondition: (OAuth.RefreshToken?) -> Bool,
			refreshClosure:
				@escaping (
					SessionState.Snapshot,
					OAuth.RefreshToken
				) async throws -> SessionState.TokenState?
		) -> Task<AccessToken, Error>?

		//auth
		var authServerRequestOptions: TokenRequestOptions { get }
	}
}
