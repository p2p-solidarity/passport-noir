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
                "MoproiOSBindings/MoproBindings.xcframework/Info.plist",
                "MoproiOSBindings/MoproBindings.xcframework/ios-arm64/libpassport_zk_mopro.a",
                "MoproiOSBindings/MoproBindings.xcframework/ios-arm64-simulator/libpassport_zk_mopro.a",
            ]
        ),
        .binaryTarget(
            name: "moproPassport",
            path: "Sources/MoproiOSBindings/MoproBindings.xcframework"
        ),
        .testTarget(
            name: "OpenPassportSwiftTests",
            dependencies: ["OpenPassportSwift"],
            path: "Tests"
        ),
    ]
)
