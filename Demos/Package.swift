// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "MastodonDemo",
    platforms: [.iOS(.v17), .macOS(.v15)],
    dependencies: [
        .package(name: "OAuth4Swift", path: ".."),
        .package(url: "https://github.com/germ-network/GermConvenience.git", from: "0.2.1"),
        .package(url: "https://github.com/apple/swift-http-types.git", from: "1.5.1"),
    ],
    targets: [
        .executableTarget(
            name: "MastodonDemo",
            dependencies: [
                .product(name: "OAuth4Swift", package: "OAuth4Swift"),
                "GermConvenience",
                .product(name: "HTTPTypes", package: "swift-http-types"),
            ],
            path: "MastodonApp/MastodonDemo"
        ),
    ]
)
