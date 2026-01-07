// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "rspl_secure_vault",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(name: "rspl-secure-vault", targets: ["rspl_secure_vault"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "rspl_secure_vault",
            dependencies: [],
            path: "../Classes",
            resources: [
                .process("../rspl_secure_vault/Sources/rspl_secure_vault/PrivacyInfo.xcprivacy")
            ]
        )
    ]
)

