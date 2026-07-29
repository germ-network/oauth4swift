import AuthenticationServices
import Foundation
import GermConvenience
import Logging
import OAuth4Swift
import Security
import SwiftUI

let redirectURI = URL(string: "mastodon-demo://oauth")!
@Observable @MainActor
final class AppState {
	var instanceDomain: String = ""
	var session: MastodonAgent?
	var userInfo: MastodonUserInfo?
	var isLoading = false
	var errorMessage: String?

	func login() async {
		guard !instanceDomain.isEmpty,
			let instance = URL(string: "https://\(instanceDomain)/")
		else { return }

		isLoading = true
		errorMessage = nil
		defer { isLoading = false }

		do {
			let client = MastodonClient(
				instance: instance,
				redirectURI: redirectURI,
				authFetcher: URLSession.manualRedirect(),
				userAuthenticator: ASWebAuthenticationSession.userAuthenticator(),
			)

			let archive = try await client.authorize(scopes: ["profile"])
			save(archive: archive)

			let agent = try await client.restore(archive: archive)
			userInfo = try await agent.fetchUserInfo()
			session = agent
		} catch let error as ASWebAuthenticationSessionError
			where error.code == .canceledLogin
		{
			// User dismissed the authenticator — not an error
		} catch {
			errorMessage = error.localizedDescription
		}
	}

	func tryRestore() async {
		guard let (archive, domain) = loadSaved(),
			let instance = URL(string: "https://\(domain)/")
		else { return }

		instanceDomain = domain
		isLoading = true
		defer { isLoading = false }

		let client = MastodonClient(
			instance: instance,
			redirectURI: redirectURI,
			authFetcher: URLSession.manualRedirect(),
			userAuthenticator: ASWebAuthenticationSession.userAuthenticator(),
		)

		do {
			let agent = try await client.restore(archive: archive)
			userInfo = try await agent.fetchUserInfo()
			session = agent
		} catch {
			clearSaved()
		}
	}

	func logout() async {
		clearSaved()
		let current = session
		session = nil
		userInfo = nil
		try? await current?.revoke()
	}

	// MARK: - Persistence

	private func save(archive: MastodonAgent.Archive) {
		guard let data = try? JSONEncoder().encode(archive) else { return }
		Keychain.save(data, key: "mastodon.archive")
		UserDefaults.standard.set(instanceDomain, forKey: "mastodon.instanceDomain")
	}

	private func loadSaved() -> (MastodonAgent.Archive, String)? {
		guard let data = Keychain.load(key: "mastodon.archive"),
			let archive = try? JSONDecoder().decode(
				MastodonAgent.Archive.self, from: data),
			let domain = UserDefaults.standard.string(forKey: "mastodon.instanceDomain")
		else { return nil }
		return (archive, domain)
	}

	private func clearSaved() {
		Keychain.delete(key: "mastodon.archive")
		UserDefaults.standard.removeObject(forKey: "mastodon.instanceDomain")
	}
}

// MARK: - Keychain

private enum Keychain {
	private static let service = Bundle.main.bundleIdentifier ?? "com.germnetwork.MastodonDemo"

	static func save(_ data: Data, key: String) {
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: key,
		]
		let attributes: [String: Any] = [kSecValueData as String: data]
		if SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
			== errSecItemNotFound
		{
			SecItemAdd(query.merging(attributes) { $1 } as CFDictionary, nil)
		}
	}

	static func load(key: String) -> Data? {
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: key,
			kSecReturnData as String: true,
			kSecMatchLimit as String: kSecMatchLimitOne,
		]
		var result: AnyObject?
		return SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess
			? result as? Data : nil
	}

	static func delete(key: String) {
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: key,
		]
		SecItemDelete(query as CFDictionary)
	}
}
