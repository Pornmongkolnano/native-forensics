// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "NativeForensics",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "ForensicsCore", targets: ["ForensicsCore"]),
        .executable(name: "NativeForensics", targets: ["NativeForensics"])
    ],
    targets: [
        .target(name: "ForensicsCore"),
        .executableTarget(name: "NativeForensics", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "FilesystemSearchBenchmark", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "ForensicsPipelineBenchmark", dependencies: ["ForensicsCore"]),
        .testTarget(name: "ForensicsCoreTests", dependencies: ["ForensicsCore"]),
        .testTarget(name: "NativeForensicsTests", dependencies: ["NativeForensics", "ForensicsCore"])
    ]
)
