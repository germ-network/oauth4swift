import Foundation
import GermConvenience

import struct HTTPTypes.HTTPFields

extension OAuth.ClientAuth {
	public struct SecretPost: SecretMethod {
		private let clientSecret: String
		public var tokenEndpointAuthMethod: TokenEndpointMethods = .clientSecretPost

		public init(clientSecret: String) {
			self.clientSecret = clientSecret
		}

		public func authenticate(
			clientId: String,
			inputs: Inputs
		) async throws -> (FormParameters, HTTPFields) {
			var params = inputs.parameters
			params["client_id"] = [clientId]
			params["client_secret"] = [clientSecret]
			return (params, inputs.headers)
		}

		public var archive: Data? {
			get throws {
				try JSONEncoder().encode(clientSecret)
			}
		}
	}
}
