// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SerbianEIDToken",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SerbianEIDPKI", targets: ["SerbianEIDPKI"]),
        .library(name: "SerbianEIDSetup", targets: ["SerbianEIDSetup"]),
        .executable(name: "seid-bench", targets: ["seid-bench"]),
    ],
    targets: [
        .target(name: "SerbianEIDPKI"),
        .target(name: "SerbianEIDSetup", resources: [.copy("Resources")]),
        .executableTarget(name: "seid-bench", dependencies: ["SerbianEIDPKI"], exclude: ["seid-bench.entitlements"]),
        .testTarget(name: "SerbianEIDPKITests", dependencies: ["SerbianEIDPKI"]),
        .testTarget(name: "SerbianEIDSetupTests", dependencies: ["SerbianEIDSetup"]),
    ]
)
