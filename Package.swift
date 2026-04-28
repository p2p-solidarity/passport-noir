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
            url: "https://github.com/p2p-solidarity/passport-noir/releases/download/v0.2.1/PassportMoproBindings.xcframework.zip",
            checksum: "abc93f45558852bde9cb2b13cb35b3837dee97d55680b79868cc812a2265efea"
        ),
        .testTarget(
            name: "OpenPassportSwiftTests",
            dependencies: ["OpenPassportSwift"],
            path: "Tests"
        ),
    ]
)
