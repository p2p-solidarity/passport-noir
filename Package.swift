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
                .byName(name: "moproPassport", condition: .when(platforms: [.iOS]))
            ],
            path: "Sources",
            exclude: [
                "MoproiOSBindings/",
            ]
        ),
        .binaryTarget(
            name: "moproPassport",
            url: "https://github.com/p2p-solidarity/passport-noir/releases/download/v0.1.0/MoproBindings.xcframework.zip",
            checksum: "36baff6d45053d5765daeeb7622a9727ab121c6a9ce49afdba9e7bd03836fa9e"
        ),
        .testTarget(
            name: "OpenPassportSwiftTests",
            dependencies: ["OpenPassportSwift"],
            path: "Tests"
        ),
    ]
)
