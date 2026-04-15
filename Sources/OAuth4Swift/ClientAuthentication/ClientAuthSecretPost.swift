import Foundation
import GermConvenience
import HTTPTypes

public struct ClientAuthSecretPost: OAuth.AuthComponent {
	private let clientSecret: String
	public var tokenEndpointAuthMethod: OAuth.TokenEndpointMethods = .clientSecretPost

	public init(clientSecret: String) {
		self.clientSecret = clientSecret
	}

	public func authenticate(
		inputs: OAuth.ClientAuthInputs
	) async throws -> (FormParameters, HTTPFields) {
		var params = inputs.parameters
		params["client_id"] = inputs.clientId
		params["client_secret"] = clientSecret
		return (params, inputs.headers)
	}
}
