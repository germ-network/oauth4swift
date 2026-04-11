import Foundation
import GermConvenience
import HTTPTypes

public struct ClientAuthSecretPost: OAuthClientAuthenticatable {
	private let clientSecret: String
	public var tokenEndpointAuthMethod = "client_secret_post"

	public init(clientSecret: String) {
		self.clientSecret = clientSecret
	}

	public init(from decoder: any Decoder) throws {
		let container = try decoder.singleValueContainer()
		self.clientSecret = try container.decode(String.self)
	}

	public func encode(to encoder: any Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(self.clientSecret)
	}

	public func authenticate(
		client: OAuthClient,
		authorizationServer: AuthServerMetadata,
		parameters: FormParameters,
		headers: HTTPFields
	) async throws -> (FormParameters, HTTPFields) {
		var params = parameters
		params["client_id"] = client.clientId
		params["client_secret"] = clientSecret
		return (params, headers)
	}
}
