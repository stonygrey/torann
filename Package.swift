// swift-tools-version: 6.0
// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import PackageDescription

let package = Package(
    name: "Torann",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "Torann", targets: ["Torann"]),
    ],
    targets: [
        .target(name: "Torann", path: "swift/Sources/Torann"),
        .testTarget(name: "TorannTests", dependencies: ["Torann"], path: "swift/Tests/TorannTests"),
        .executableTarget(name: "TorannInterop", dependencies: ["Torann"], path: "swift/Sources/TorannInterop"),
    ],
    swiftLanguageModes: [.v6]
)
