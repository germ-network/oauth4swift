import GermConvenience
import HTTPTypes

extension OAuth {
	public protocol ClientAuthenticatable: Sendable {
		var tokenEndpointAuthMethod: TokenEndpointMethods { get }

		func authenticate(
			authServerMetadata: AuthServerMetadata,
			parameters: FormParameters,
			headers: HTTPFields,
		) async throws
			-> (FormParameters, HTTPFields)
	}

}
