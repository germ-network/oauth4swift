import Foundation
import GermConvenience
import HTTPTypes

// Usage not recommended, use ClientAuthSecretPost
public struct ClientAuthSecretBasic: OAuth.ClientAuthComponent {
	private let clientSecret: String
	public var tokenEndpointAuthMethod: OAuth.TokenEndpointMethods = .clientSecretBasic

	public init(clientSecret: String) {
		self.clientSecret = clientSecret
	}

	public func authenticate(
		clientId: String,
		inputs: OAuth.ClientAuthInputs
	) async throws -> (FormParameters, HTTPFields) {
		let basicAuth = [
			clientId,
			clientSecret,
		].joined(separator: ":")

		var headers = inputs.headers
		// Replace the authorization header:
		headers[.authorization] = basicAuth.utf8Data.base64EncodedString()

		return (inputs.parameters, headers)
	}

	public var archive: Data? {
		get throws {
			try JSONEncoder().encode(clientSecret)
		}
	}
}
