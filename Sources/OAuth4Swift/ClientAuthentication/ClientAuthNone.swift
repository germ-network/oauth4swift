import Foundation
import GermConvenience
import HTTPTypes

extension OAuth {
	public struct ClientAuthNone: ClientAuthenticatable {
		public var tokenEndpointAuthMethod = "none"
		
		public func authenticate(
			inputs: OAuth.ClientAuthInputs
		) async throws -> (FormParameters, HTTPFields) {
			var params = inputs.parameters
			params["client_id"] = inputs.clientId
			return (params, inputs.headers)
		}
	}
}
