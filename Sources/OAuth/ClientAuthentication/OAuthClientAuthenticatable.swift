import GermConvenience
import HTTPTypes

public protocol OAuthClientAuthenticatable: Codable, Hashable, Sendable {
	func authenticate(
		client: OAuthClient,
		authorizationServer: AuthServerMetadata,
		parameters: FormParameters,
		headers: HTTPFields,
	) async throws
		-> (FormParameters, HTTPFields)
}
