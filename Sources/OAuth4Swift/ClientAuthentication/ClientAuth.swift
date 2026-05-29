//
//  ClientAuth.swift
//  OAuth
//
//  Created by Mark @ Germ on 2/22/26 from OAuthenticator
//

import Foundation
import GermConvenience

import struct HTTPTypes.HTTPFields

extension OAuth {
	public enum ClientAuth {
		public struct Inputs: Sendable {
			public let authServerMetadata: AuthServerMetadata
			public let parameters: FormParameters
			public let headers: HTTPFields
		}

		public protocol Method: Sendable {
			var tokenEndpointAuthMethod: TokenEndpointMethods { get }
			func authenticate(clientId: String, inputs: Inputs) async throws -> (
				FormParameters, HTTPFields
			)
		}

		/// Refinement of Method for auth methods that use a client secret.
		/// Excludes `None`, which is for public clients.
		public protocol SecretMethod: Method {
			var archive: Data? { get throws }
		}
	}
}
