// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "sdk-smoke-swift",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "sdk-smoke-swift", targets: ["SDKSmokeSwift"])],
    dependencies: [.package(url: "https://github.com/firebase/firebase-ios-sdk.git", exact: "12.18.0")],
    targets: [
        .target(name: "SmokeSupport"),
        .executableTarget(name: "SDKSmokeSwift", dependencies: [
            "SmokeSupport",
            .product(name: "FirebaseCore", package: "firebase-ios-sdk"),
            .product(name: "FirebaseAuth", package: "firebase-ios-sdk"),
            .product(name: "FirebaseFirestore", package: "firebase-ios-sdk"),
            .product(name: "FirebaseStorage", package: "firebase-ios-sdk"),
            .product(name: "FirebaseDatabase", package: "firebase-ios-sdk"),
        ]),
        .testTarget(name: "SmokeSupportTests", dependencies: ["SmokeSupport"]),
    ],
    swiftLanguageModes: [.v5]
)
