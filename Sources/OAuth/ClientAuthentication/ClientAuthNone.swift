import Foundation
import GermConvenience
import HTTPTypes

public struct ClientAuthNone: OAuthClientAuthenticatable {
	public var tokenEndpointAuthMethod = "none"

	public init() {}
	public init(from decoder: any Decoder) throws {}
	public func encode(to encoder: any Encoder) throws {}

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
}
