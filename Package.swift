// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "OAuth",
	platforms: [.iOS(.v16), .macOS(.v15)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "OAuth",
			targets: ["OAuth"]
		)
	],
	dependencies: [
		.package(
			url: "https://github.com/germ-network/GermConvenience.git",
			from: "0.1.0"
		),
		.package(url: "https://github.com/apple/swift-http-types.git", from: "1.5.1"),
		.package(
			url: "https://github.com/apple/swift-crypto.git",
			.upToNextMajor(from: "4.2.0")),
		.package(url: "https://github.com/apple/swift-log", from: "1.6.0"),
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "OAuth",
			dependencies: [
				"GermConvenience",
				.product(name: "Crypto", package: "swift-crypto"),
				.product(name: "HTTPTypes", package: "swift-http-types"),
				.product(name: "Logging", package: "swift-log"),
			]
		),
		.testTarget(
			name: "OAuthTests",
			dependencies: ["OAuth"]
		),
	]
)
