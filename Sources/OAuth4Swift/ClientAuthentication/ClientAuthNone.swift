import Foundation
import GermConvenience
import HTTPTypes

///We provide components that implement these methods, but because they encapsulate mutable state,
///Oauth expects to interact with the protocol through an implementation of SessionCapabilities
///which inherits from ClientAuthenticatable
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
