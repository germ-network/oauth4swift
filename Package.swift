// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "OAuth4Swift",
	// iOS 18 / macOS 15. The floor is set by swift-secret-bytes 0.5.0 (the
	// swift-crypto-5 release this package now rides for zeroizing secret
	// custody), which declares iOS 18 / macOS 15.
	platforms: [.iOS(.v18), .macOS(.v15)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "OAuth4Swift",
			targets: ["OAuth4Swift"]
		)
	],
	dependencies: [
		.package(
			url: "https://github.com/germ-network/GermConvenience.git",
			// 0.10.0 is its swift-crypto-5 release — the revision pin drops.
			from: "0.10.0"
		),
		.package(url: "https://github.com/swift-libp2p/swift-bases.git", from: "0.2.0"),
		.package(url: "https://github.com/apple/swift-http-types.git", from: "1.5.1"),
		.package(
			url: "https://github.com/apple/swift-crypto.git",
			from: "5.0.0"),
		.package(url: "https://github.com/apple/swift-log", from: "1.6.0"),
		// Zeroizing custody for the secrets this package carries — the DPoP
		// P-256 private scalar and the access/refresh token values — plus the
		// shared `SecretBytes`<->`String` text bridge (`utf8String()`), which
		// moved here rather than living in this package.
		//
		// 0.6.0 adds the shared `SecretBytes`<->`String` text bridge
		// (germ-network/swift-secret-bytes#16) this package uses.
		// `from:` rather than `.upToNextMinor` so later 0.x releases are not
		// fenced off.
		.package(
			url: "https://github.com/germ-network/swift-secret-bytes.git",
			from: "0.6.0"
		),
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "OAuth4Swift",
			dependencies: [
				"GermConvenience",
				.product(name: "GermConvenienceHTTP", package: "GermConvenience"),
				.product(name: "Crypto", package: "swift-crypto"),
				.product(name: "HTTPTypes", package: "swift-http-types"),
				.product(name: "Logging", package: "swift-log"),
				.product(name: "Base64", package: "swift-bases"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
			]
		),
		.testTarget(
			name: "OAuth4SwiftTests",
			dependencies: [
				"OAuth4Swift",
				.product(name: "GermConvenienceMocks", package: "GermConvenience"),
				.product(name: "GermConvenienceHTTP", package: "GermConvenience"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
			]
		),
	]
)
