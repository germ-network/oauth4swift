import Foundation
import GermConvenience
import HTTPTypes

// Usage not recommended, use ClientAuthSecretPost
public struct ClientAuthSecretBasic: OAuth.ClientAuthenticatable {
	private let clientSecret: String
	public var tokenEndpointAuthMethod: OAuth.TokenEndpointMethods = .clientSecretBasic

	public init(clientSecret: String) {
		self.clientSecret = clientSecret
	}

	public func authenticate(
		inputs: OAuth.ClientAuthInputs
	) async throws -> (FormParameters, HTTPFields) {
		let basicAuth = [
			inputs.clientId,
			clientSecret,
		].joined(separator: ":")

		var headers = inputs.headers
		// Replace the authorization header:
		headers[.authorization] = basicAuth.utf8Data.base64EncodedString()

		return (inputs.parameters, headers)
	}
}
