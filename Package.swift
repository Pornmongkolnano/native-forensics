// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "NativeForensics",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "ForensicsCore", targets: ["ForensicsCore"]),
        .executable(name: "NativeForensics", targets: ["NativeForensics"]),
        .executable(name: "NFDocumentDecoder", targets: ["NFDocumentDecoder"]),
        .executable(name: "AutopsyUDFExport", targets: ["AutopsyUDFExport"])
    ],
    targets: [
        .systemLibrary(name: "CSQLite3"),
        .target(name: "ForensicsCore", dependencies: ["CSQLite3"]),
        .executableTarget(name: "NativeForensics", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "NFDocumentDecoder", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "AutopsyUDFExport", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "FilesystemSearchBenchmark", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "ForensicsPipelineBenchmark", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "AssignmentWorkflowProbe", dependencies: ["ForensicsCore"]),
        .testTarget(name: "ForensicsCoreTests", dependencies: ["ForensicsCore", "NFDocumentDecoder"]),
        .testTarget(name: "NativeForensicsTests", dependencies: ["NativeForensics", "ForensicsCore"])
    ]
)
