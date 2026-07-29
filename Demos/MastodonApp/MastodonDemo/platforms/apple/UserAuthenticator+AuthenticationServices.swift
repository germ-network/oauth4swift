//
//  UserAuthenticator+AuthenticationServices.swift
//  AtprotoOAuth
//
//  Created by Mark @ Germ on 2/19/26 from OAuthenticate
//

import OAuth4Swift

enum WebAuthenticationSessionError: Error {
	case resultInvalid
}

#if canImport(AuthenticationServices)
	import AuthenticationServices

	extension ASWebAuthenticationSession {
		static public func userAuthenticator() -> UserAuthenticator {
			{
				try await begin(with: $0, callbackURLScheme: $1)
			}
		}

		public static func begin(with url: URL, callbackURLScheme scheme: String)
			async throws -> URL
		{
			try await begin(
				with: url,
				callbackURLScheme: scheme,
				contextProvider: CredentialWindowProvider()
			)
		}

		@MainActor
		public static func begin(
			with url: URL, callbackURLScheme scheme: String,
			contextProvider: ASWebAuthenticationPresentationContextProviding
		) async throws -> URL {
			try await withCheckedThrowingContinuation { continuation in
				let session = ASWebAuthenticationSession(
					url: url,
					callbackURLScheme: scheme,
					completionHandler: { callbackURL, error in
						switch (callbackURL, error) {
						case (_, let error?):
							continuation.resume(with: .failure(error))
						case (let callbackURL?, nil):
							continuation.resume(
								with: .success(callbackURL))
						default:
							continuation.resume(
								with: .failure(
									WebAuthenticationSessionError
										.resultInvalid))
						}
					}
				)

				if #available(macCatalyst 13.1, *) {
					session.prefersEphemeralWebBrowserSession = true
				}

				session.presentationContextProvider = contextProvider

				session.start()
			}
		}
	}
#endif  //canImport(AuthenticationServices)
