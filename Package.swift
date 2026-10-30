// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "OpenPassportSwift",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "OpenPassportSwift",
            targets: ["OpenPassportSwift"]
        ),
    ],
    targets: [
        .target(
            name: "OpenPassportSwift",
            dependencies: [
                .byName(name: "passportMoproBindings", condition: .when(platforms: [.iOS]))
            ],
            path: "Sources",
            exclude: [
                "MoproiOSBindings/MoproBindings.xcframework",
            ]
        ),
        .binaryTarget(
            name: "passportMoproBindings",
            url: "https://github.com/p2p-solidarity/passport-noir/releases/download/v0.5.0/PassportMoproBindings.xcframework.zip",
            checksum: "31e7b01ef6faa86909f311a0c47a9f8c7308efda8194aed12f93ad8e351e9175"
        ),
        .testTarget(
            name: "OpenPassportSwiftTests",
            dependencies: ["OpenPassportSwift"],
            path: "Tests"
        ),
    ]
)
