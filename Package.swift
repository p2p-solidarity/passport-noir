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
            url: "https://github.com/p2p-solidarity/passport-noir/releases/download/v0.4.0/PassportMoproBindings.xcframework.zip",
            checksum: "f397c013d69beced9c4299673c91884cdb02c900c0ff9a32de3869988cd3f49e"
        ),
        .testTarget(
            name: "OpenPassportSwiftTests",
            dependencies: ["OpenPassportSwift"],
            path: "Tests"
        ),
    ]
)
