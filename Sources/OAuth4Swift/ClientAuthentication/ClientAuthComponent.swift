//
//  AuthComponent.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 4/15/26.
//

import Foundation
import GermConvenience
import HTTPTypes

extension OAuth {
	public protocol ClientAuthComponent: Sendable {
		var tokenEndpointAuthMethod: TokenEndpointMethods { get }

		func authenticate(
			clientId: String,
			inputs: OAuth.ClientAuthInputs
		) async throws
			-> (FormParameters, HTTPFields)

		var archive: Data? { get throws }
	}

	public typealias ClientAuthComponentFactory =
		@Sendable (
			TokenEndpointMethods,
			Data?
		) throws -> any ClientAuthComponent

	public static let DefaultClientAuthComponentFactory: ClientAuthComponentFactory = {
		method,
		archive in
		switch method {
		case .none:
			return ClientAuthNone()
		case .clientSecretBasic:
			return ClientAuthSecretBasic(
				clientSecret: try JSONDecoder().decode(
					String.self,
					from: archive.tryUnwrap
				)
			)
		case .clientSecretPost:
			return ClientAuthSecretPost(
				clientSecret: try JSONDecoder().decode(
					String.self,
					from: archive.tryUnwrap
				)
			)
		default:
			throw OAuth.Errors.notImplemented
		}
	}
}
