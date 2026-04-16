import Foundation
import GermConvenience
import HTTPTypes

public struct ClientAuthSecretPost: OAuth.ClientAuthComponent {
	private let clientSecret: String
	public var tokenEndpointAuthMethod: OAuth.TokenEndpointMethods = .clientSecretPost

	public init(clientSecret: String) {
		self.clientSecret = clientSecret
	}

	public func authenticate(
		clientId: String,
		inputs: OAuth.ClientAuthInputs
	) async throws -> (FormParameters, HTTPFields) {
		var params = inputs.parameters
		params["client_id"] = clientId
		params["client_secret"] = clientSecret
		return (params, inputs.headers)
	}

	public var archive: Data? {
		get throws {
			try JSONEncoder().encode(clientSecret)
		}
	}
}
