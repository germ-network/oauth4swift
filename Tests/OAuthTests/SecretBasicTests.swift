import Foundation
import Testing

import struct HTTPTypes.HTTPFields

@testable import OAuth4Swift

@Test func secretBasicHeaderMatchesRFC6749Example() async throws {
	let auth = OAuth.ClientAuth.SecretBasic(clientSecret: "gX1fBat3bV")
	let inputs = OAuth.ClientAuth.Inputs(
		authServerMetadata: try .mock(),
		parameters: .init(),
		headers: .init()
	)

	let (parameters, headers) = try await auth.authenticate(
		clientId: "s6BhdRkqt3",
		inputs: inputs
	)

	#expect(headers[.authorization] == "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW")
	#expect(parameters == inputs.parameters)
}

@Test func secretBasicFormURLEncodesCredentials() async throws {
	let auth = OAuth.ClientAuth.SecretBasic(clientSecret: "s3cr3t+/=")
	let inputs = OAuth.ClientAuth.Inputs(
		authServerMetadata: try .mock(),
		parameters: .init(),
		headers: .init()
	)

	let (_, headers) = try await auth.authenticate(
		clientId: "client id:one",
		inputs: inputs
	)

	// base64("client%20id%3Aone:s3cr3t%2B/%3D")
	#expect(headers[.authorization] == "Basic Y2xpZW50JTIwaWQlM0FvbmU6czNjcjN0JTJCLyUzRA==")
}
