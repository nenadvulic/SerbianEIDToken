// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SerbianEIDToken",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SerbianEIDPKI", targets: ["SerbianEIDPKI"]),
        .executable(name: "seid-bench", targets: ["seid-bench"]),
    ],
    targets: [
        .target(name: "SerbianEIDPKI"),
        .executableTarget(name: "seid-bench", dependencies: ["SerbianEIDPKI"]),
        .testTarget(name: "SerbianEIDPKITests", dependencies: ["SerbianEIDPKI"]),
    ]
)
