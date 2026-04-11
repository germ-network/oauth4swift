import GermConvenience
import HTTPTypes

public protocol OAuthClientAuthenticatable: Codable, Hashable, Sendable {
	var tokenEndpointAuthMethod: String { get }

	func authenticate(
		client: OAuthClient,
		authorizationServer: AuthServerMetadata,
		parameters: FormParameters,
		headers: HTTPFields,
	) async throws
		-> (FormParameters, HTTPFields)

	func encode(to encoder: any Encoder) throws
	init(from decoder: any Decoder) throws
}
