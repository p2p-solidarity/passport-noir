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
            url: "https://github.com/p2p-solidarity/passport-noir/releases/download/v0.3.0/PassportMoproBindings.xcframework.zip",
            checksum: "19945b519bc25c40fd446c9d5f9214adef8dbab259623f7f7a810be506f4556d"
        ),
        .testTarget(
            name: "OpenPassportSwiftTests",
            dependencies: ["OpenPassportSwift"],
            path: "Tests"
        ),
    ]
)
