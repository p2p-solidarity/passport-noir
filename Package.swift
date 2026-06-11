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
            url: "https://github.com/p2p-solidarity/passport-noir/releases/download/v0.3.2/PassportMoproBindings.xcframework.zip",
            checksum: "964b32a5a725bfd3eb48935bbcd5f2a3bf127a7c558f4a157e836e716b690dd1"
        ),
        .testTarget(
            name: "OpenPassportSwiftTests",
            dependencies: ["OpenPassportSwift"],
            path: "Tests"
        ),
    ]
)
