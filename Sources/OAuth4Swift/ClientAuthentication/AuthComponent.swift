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
	public protocol AuthComponent: Sendable {
		var tokenEndpointAuthMethod: TokenEndpointMethods { get }

		func authenticate(
			inputs: OAuth.ClientAuthInputs
		) async throws
			-> (FormParameters, HTTPFields)
	}
}
