//
//  Component.swift
//  OAuth4Swift
//
//  Created by Mark @ Germ on 4/15/26.
//

import Foundation
import GermConvenience
import HTTPTypes

extension OAuth.ClientAuth {
	public protocol Component: Sendable {
		var tokenEndpointAuthMethod: TokenEndpointMethods { get }

		func authenticate(
			clientId: String,
			inputs: OAuth.ClientAuth.Inputs
		) async throws
			-> (FormParameters, HTTPFields)

		var archive: Data? { get throws }
	}

	public typealias ComponentFactory =
		@Sendable (
			TokenEndpointMethods,
			Data?
		) throws -> any Component

	public static let defaultFactory: ComponentFactory = {
		method,
		archive in
		switch method {
		case .none:
			return None()
		case .clientSecretBasic:
			return SecretBasic(
				clientSecret: try JSONDecoder().decode(
					String.self,
					from: archive.tryUnwrap
				)
			)
		case .clientSecretPost:
			return SecretPost(
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
