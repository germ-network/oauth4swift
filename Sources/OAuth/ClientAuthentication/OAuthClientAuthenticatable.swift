import GermConvenience
import HTTPTypes

public protocol OAuthClientAuthenticatable: Sendable {
	var tokenEndpointAuthMethod: String { get }

	func authenticate(
		inputs: OAuthComponents.ClientAuthInputs
	) async throws
		-> (FormParameters, HTTPFields)
}
