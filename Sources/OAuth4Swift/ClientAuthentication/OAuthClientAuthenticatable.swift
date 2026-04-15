import GermConvenience
import HTTPTypes

extension OAuth {
	public protocol ClientAuthenticatable: Sendable {
		var tokenEndpointAuthMethod: TokenEndpointMethods { get }

		func authenticate(
			inputs: OAuth.ClientAuthInputs
		) async throws
			-> (FormParameters, HTTPFields)
	}
}
