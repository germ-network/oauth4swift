import Foundation
import GermConvenience
import HTTPTypes
import Logging
import OAuth4Swift

// MARK: - Fix for GermConvenience
extension HTTPResponseError: @retroactive LocalizedError {
	public var errorDescription: String? {
		switch self {
		case .unsuccessful(let code, let data):
			let body = String(data: data, encoding: .utf8) ?? "<\(data.count) bytes>"
			return "HTTP \(code): \(body)"
		case .unsuccessfulString(let code, let string):
			return "HTTP \(code): \(string)"
		}
	}
}

// MARK: - App Registration

struct MastodonAppCredentials: Sendable, Decodable {
	let clientId: String
	let clientSecret: String

	enum CodingKeys: String, CodingKey {
		case clientId = "client_id"
		case clientSecret = "client_secret"
	}
}

func registerMastodonApp(instance: URL) async throws -> MastodonAppCredentials {
	let json = try JSONEncoder().encode([
		"client_name": "MastodonOAuthDemo",
		"redirect_uris": "mastodon-demo://oauth",
		"scopes": "profile",
	])
	let headers: HTTPFields = [
		.contentType: HTTPContentType.json.rawValue,
		.accept: HTTPContentType.json.rawValue,
	]
	let request = try BundledHTTPRequest(
		method: .post,
		url: instance.appending(path: "/api/v1/apps"),
		headerFields: headers,
		body: json
	)

	return try await URLSession.manualRedirect().data(for: request)
		.expectSuccess()
		.decode()
}

// MARK: - User Info

nonisolated struct MastodonUserInfo: Decodable, Sendable {
	let name: String?
	let preferredUsername: String?
	let picture: URL?

	enum CodingKeys: String, CodingKey {
		case name
		case preferredUsername = "preferred_username"
		case picture
	}
}

// MARK: - Token Options

// Mastodon has no meaningful token validation beyond it existing.
struct MastodonTokenOptions: OAuth.TokenAuthorizeOptions {
	typealias ValidationOutput = Void

	func validate(
		tokenResponse: TokenEndpointResponse,
		authServerMetadata: AuthServerMetadata
	) async throws {}
}

struct MastodonTokenRefreshOptions: OAuth.TokenRefreshOptions {
	func validate(
		tokenResponse: TokenEndpointResponse,
		authServerMetadata: AuthServerMetadata,
		previousState: OAuth.SessionState.Snapshot
	) async throws -> Bool {
		tokenResponse.refreshToken != nil
			|| previousState.grantScopes?.contains("offline_access") == true
	}
}

// MARK: - Session

enum MastodonClientError: LocalizedError {
	case missingSecret

	var errorDescription: String? {
		"The client_secret was missing from the archive."
	}
}

enum MastodonSessionError: LocalizedError {
	case missingUserinfoEndpoint

	var errorDescription: String? {
		"This Mastodon instance does not expose a userinfo endpoint (requires 4.3+)"
	}
}

// Analogous to AtprotoOAuthAgent: actor conforming to OAuth.SessionCapabilities so
// fetchUserInfo() and revoke() both route through authResponse(for:), which handles
// Bearer attachment and DPoP nonce retry transparently.
actor MastodonAgent: OAuth.SessionCapabilities {
	public struct Archive: Sendable, Codable {
		public var clientId: String
		public var session: OAuth.SessionState.Archive?
		public var clientAuthArchive: Data?

		public init(clientId: String, session: OAuth.SessionState.Archive?, clientAuthArchive: Data?) {
			self.clientId = clientId
			self.session = session
			self.clientAuthArchive = clientAuthArchive
		}
	}

	// MARK: Stored state

	public nonisolated let clientId: String
	public nonisolated let authFetcher: HTTPFetcher
	public nonisolated let clientAuth: any OAuth.ClientAuth.SecretMethod
	private let metadata: AuthServerMetadata
	private let tokenState: OAuth.SessionState.TokenState

	// MARK: Init / restore

	init(
		archive: OAuth.SessionState.Archive,
		metadata: AuthServerMetadata,
		clientId: String,
		clientAuth: any OAuth.ClientAuth.SecretMethod,
		authFetcher: HTTPFetcher
	) {
		self.clientId = clientId
		self.metadata = metadata
		self.tokenState = archive.tokenState
		self.clientAuth = clientAuth
		self.authFetcher = authFetcher
	}

	static func restore(
		archive: OAuth.SessionState.Archive,
		metadata: AuthServerMetadata,
		clientId: String,
		clientAuth: any OAuth.ClientAuth.SecretMethod,
	) -> MastodonAgent {
		.init(
			archive: archive,
			metadata: metadata,
			clientId: clientId,
			clientAuth: clientAuth,
			authFetcher: URLSession.manualRedirect()
		)
	}

	// MARK: - OAuth.SessionCapabilities

	var authServerMetadata: AuthServerMetadata {
		get async throws { metadata }
	}

	var authToken: OAuth.AccessToken {
		get async throws { tokenState.accessToken }
	}

	// Mastodon access tokens don't expire and have no refresh tokens.
	func startRefresh(
		continueCondition: (OAuth.RefreshToken?) -> Bool,
		refreshClosure:
			@escaping @concurrent (
				OAuth.SessionState.Snapshot,
				OAuth.RefreshToken
			) async throws -> OAuth.SessionState.TokenState?
	) -> Task<OAuth.AccessToken, Error>? { nil }

	var tokenRefreshOptions: any OAuth.TokenRefreshOptions {
		MastodonTokenRefreshOptions()
	}
}

extension MastodonAgent: OAuth.ClientAuth.Authenticable {
	public nonisolated var tokenEndpointAuthMethod: OAuth.ClientAuth.TokenEndpointMethods {
		clientAuth.tokenEndpointAuthMethod
	}

	public func authenticate(inputs: OAuth.ClientAuth.Inputs) async throws -> (
		FormParameters,
		HTTPFields
	) {
		try await clientAuth.authenticate(clientId: clientId, inputs: inputs)
	}
}

// MARK: - API
extension MastodonAgent {
	func fetchUserInfo() async throws -> MastodonUserInfo {
		guard let endpoint = metadata.userinfoEndpoint else {
			throw MastodonSessionError.missingUserinfoEndpoint
		}
		let request = try BundledHTTPRequest(method: .get, url: endpoint)
		let response = try await authResponse(for: request)
		return try JSONDecoder().decode(MastodonUserInfo.self, from: response.data)
	}

	func revoke() async throws {
		try await revocationRequest(
			authServerMetadata: metadata,
			token: tokenState.accessToken
		)
	}
}

// MARK: - Authorizer

public struct MastodonClient: Sendable {
	public let instance: URL
	let authFetcher: HTTPFetcher
	let userAuthenticator: UserAuthenticator

	public init(
		instance: URL,
		authFetcher: HTTPFetcher,
		userAuthenticator: @escaping UserAuthenticator
	) {
		self.instance = instance
		self.authFetcher = authFetcher
		self.userAuthenticator = userAuthenticator
	}
}

extension MastodonClient {
	func authorize() async throws -> MastodonAgent.Archive {
		guard let metadata = try await authFetcher.authServerDiscovery(endpoint: instance)
		else { throw OAuth.Errors.notSupported }

		// In production, cache per instance to avoid Mastodon's app registration explosion problem
		let credentials = try await registerMastodonApp(instance: instance)
		let clientAuth = OAuth.ClientAuth.SecretPost(clientSecret: credentials.clientSecret)

		let authorizer = Authorizer(
			clientId: credentials.clientId,
			clientAuth: clientAuth,
			authorizeInputs:
				.init(
					clientInfo: .init(
						clientId: credentials.clientId,
						scopes: ["profile"],
						redirectURI: URL(string: "mastodon-demo://oauth")!
					),
					authServerMetadata: metadata,
					authEndpoint: metadata.authorizationEndpoint,
					inputToken: nil,
					additionalParameters: nil,
					userAuthenticator: userAuthenticator,
					tokenAuthOptions: MastodonTokenOptions(),
				),
			authFetcher: authFetcher,
		)

		let (sessionArchive, _) = try await authorizer.performUserAuthentication()

		return MastodonAgent.Archive(
			clientId: credentials.clientId,
			session: sessionArchive,
			clientAuthArchive: authorizer.clientAuthArchive
		)
	}

	actor Authorizer: OAuth.Authorizer {
		let clientId: String
		let authorizeInputs: OAuth.AuthorizeInputs<MastodonTokenOptions>
		let authFetcher: any HTTPFetcher

		let clientAuth: any OAuth.ClientAuth.SecretMethod
		let tokenEndpointAuthMethod: OAuth.ClientAuth.TokenEndpointMethods

		init(
			clientId: String,
			clientAuth: any OAuth.ClientAuth.SecretMethod,
			authorizeInputs: OAuth.AuthorizeInputs<MastodonTokenOptions>,
			authFetcher: any HTTPFetcher,
		) {
			self.clientId = clientId
			self.clientAuth = clientAuth
			self.authorizeInputs = authorizeInputs
			self.authFetcher = authFetcher

			self.tokenEndpointAuthMethod = clientAuth.tokenEndpointAuthMethod
		}
	}
}

extension MastodonClient.Authorizer {
	func authenticate(inputs: OAuth.ClientAuth.Inputs) async throws -> (
		FormParameters,
		HTTPFields
	) {
		try await clientAuth.authenticate(
			clientId: clientId,
			inputs: inputs
		)
	}

	nonisolated var clientAuthArchive: Data? {
		try? clientAuth.archive
	}
}

extension MastodonClient {
	func restore(archive: MastodonAgent.Archive) async throws -> MastodonAgent {
		guard let data = archive.clientAuthArchive,
			let secret = try? JSONDecoder().decode(String.self, from: data),
			let sessionArchive = archive.session
		else { throw MastodonClientError.missingSecret }

		guard let metadata = try await authFetcher.authServerDiscovery(endpoint: instance)
		else { throw OAuth.Errors.notSupported }

		return MastodonAgent.restore(
			archive: sessionArchive,
			metadata: metadata,
			clientId: archive.clientId,
			clientAuth: OAuth.ClientAuth.SecretPost(clientSecret: secret)
		)
	}
}
