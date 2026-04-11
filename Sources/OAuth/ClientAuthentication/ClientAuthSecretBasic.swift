import Foundation
import GermConvenience
import HTTPTypes

public struct ClientAuthSecretBasic: OAuthClientAuthenticatable {
	private let clientSecret: String
	public var tokenEndpointAuthMethod = "client_secret_basic"

	public init(clientSecret: String) {
		self.clientSecret = clientSecret
	}

	public init(from decoder: any Decoder) throws {
		let container = try decoder.singleValueContainer()
		self.clientSecret = try container.decode(String.self)
	}

	public func encode(to encoder: any Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(self.clientSecret)
	}

	public func authenticate(
		client: OAuthClient,
		authorizationServer: AuthServerMetadata,
		parameters: FormParameters,
		headers: HTTPFields
	) async throws -> (FormParameters, HTTPFields) {
		let basicAuth = [
			client.clientId,
			clientSecret,
		].joined(separator: ":")

		var headers = headers
		// Replace the authorization header:
		headers[.authorization] = basicAuth.utf8Data.base64EncodedString()

		return (parameters, headers)
	}
}
