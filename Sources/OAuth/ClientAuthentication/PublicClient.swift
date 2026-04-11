import Foundation
import GermConvenience
import HTTPTypes

public struct ClientAuthNone: OAuthClientAuthenticatable {
	let clientId: String

	public init(clientId: String) {
		self.clientId = clientId
	}

	public func authenticate(
		client: OAuthClient,
		authorizationServer: AuthServerMetadata,
		parameters: FormParameters,
		headers: HTTPFields
	) async throws -> (FormParameters, HTTPFields) {
		var params = parameters
		params["client_id"] = client.clientId
		return (params, headers)
	}

	public func encode(to encoder: any Encoder) throws {}
}
