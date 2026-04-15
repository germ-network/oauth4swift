import Foundation
import GermConvenience
import HTTPTypes

public struct ClientAuthNone: OAuthClientAuthenticatable {
	public var tokenEndpointAuthMethod = "none"

	public func authenticate(
		inputs: OAuthComponents.ClientAuthInputs
	) async throws -> (FormParameters, HTTPFields) {
		var params = inputs.parameters
		params["client_id"] = inputs.clientId
		return (params, inputs.headers)
	}
}
