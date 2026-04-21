import GermConvenience
import HTTPTypes

public protocol OAuthClientAuthenticatable: Sendable {
	var tokenEndpointAuthMethod: String { get }

	func authenticate(
		client: OAuthClient,
		authorizationServer: AuthServerMetadata,
		parameters: FormParameters,
		headers: HTTPFields,
	) async throws
		-> (FormParameters, HTTPFields)
}
