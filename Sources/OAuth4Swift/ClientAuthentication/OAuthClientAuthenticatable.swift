import GermConvenience
import HTTPTypes

extension OAuth {
	public protocol ClientAuthenticatable: Sendable {
		var tokenEndpointAuthMethod: String { get }
		
		func authenticate(
			inputs: OAuth.ClientAuthInputs
		) async throws
		-> (FormParameters, HTTPFields)
	}
}
