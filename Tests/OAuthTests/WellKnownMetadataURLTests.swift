import Foundation
import Testing

@testable import OAuth4Swift

@Suite("well-known metadata URL construction")
struct WellKnownMetadataURLTests {
	@Test("Resource identifier without a path")
	func noPath() throws {
		let source = try #require(URL(string: "https://api.example.com"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com/.well-known/oauth-protected-resource"
		)
	}

	@Test("Root-only path is normalized to the no-path form")
	func rootPathOnly() throws {
		let source = try #require(URL(string: "https://api.example.com/"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com/.well-known/oauth-protected-resource"
		)
	}

	@Test("Trailing slash on the resource path is stripped (RFC 8414 §3.1)")
	func trailingSlashStripped() throws {
		let source = try #require(URL(string: "https://api.example.com/xrpc/"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com/.well-known/oauth-protected-resource/xrpc"
		)
	}

	@Test("Multiple trailing slashes are all stripped")
	func multipleTrailingSlashesStripped() throws {
		let source = try #require(URL(string: "https://api.example.com/xrpc///"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com/.well-known/oauth-protected-resource/xrpc"
		)
	}

	@Test("Resource identifier with a single path segment")
	func singleSegment() throws {
		let source = try #require(URL(string: "https://api.example.com/xrpc"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com/.well-known/oauth-protected-resource/xrpc"
		)
	}

	@Test("Resource identifier with a multi-segment path")
	func multipleSegments() throws {
		let source = try #require(URL(string: "https://api.example.com/a/b/c"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com/.well-known/oauth-protected-resource/a/b/c"
		)
	}

	@Test("Percent-encoded path segments are preserved")
	func percentEncodedPath() throws {
		let source = try #require(URL(string: "https://api.example.com/user%20name"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com/.well-known/oauth-protected-resource/user%20name"
		)
	}

	@Test("Query string is preserved")
	func queryPreserved() throws {
		let source = try #require(URL(string: "https://api.example.com/xrpc?tenant=foo"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com/.well-known/oauth-protected-resource/xrpc?tenant=foo"
		)
	}

	@Test("Non-default port is preserved")
	func nonDefaultPort() throws {
		let source = try #require(URL(string: "https://api.example.com:8443/xrpc"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com:8443/.well-known/oauth-protected-resource/xrpc"
		)
	}

	@Test("Fragment is dropped")
	func fragmentDropped() throws {
		let source = try #require(URL(string: "https://api.example.com/xrpc#frag"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		#expect(
			built.absoluteString
				== "https://api.example.com/.well-known/oauth-protected-resource/xrpc"
		)
	}

	@Test("Authorization server issuer with a path")
	func authorizationServerIssuer() throws {
		let source = try #require(URL(string: "https://issuer.example.com/tenant1"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownAuthorizationServer)
		#expect(
			built.absoluteString
				== "https://issuer.example.com/.well-known/oauth-authorization-server/tenant1"
		)
	}

	@Test("Authorization server issuer without a path")
	func authorizationServerIssuerNoPath() throws {
		let source = try #require(URL(string: "https://issuer.example.com"))
		let built = try source.insertingWellKnownSegment(OAuth.wellKnownAuthorizationServer)
		#expect(
			built.absoluteString
				== "https://issuer.example.com/.well-known/oauth-authorization-server"
		)
	}

	@Test("URL without a host throws missingScheme")
	func missingHostThrows() throws {
		let source = try #require(URL(string: "https:///path"))
		#expect(throws: OAuth.Errors.self) {
			try source.insertingWellKnownSegment(OAuth.wellKnownProtectedResource)
		}
	}
}
