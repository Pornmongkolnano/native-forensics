// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "NativeForensics",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "ForensicsCore", targets: ["ForensicsCore"]),
        .executable(name: "NativeForensics", targets: ["NativeForensics"]),
        .executable(name: "NFDocumentDecoder", targets: ["NFDocumentDecoder"]),
        .executable(name: "NFDocumentDecoderXPC", targets: ["NFDocumentDecoderXPC"]),
        .executable(name: "NFDocumentDecoderWorker", targets: ["NFDocumentDecoderWorker"]),
        .executable(name: "AutopsyUDFExport", targets: ["AutopsyUDFExport"])
    ],
    targets: [
        .systemLibrary(name: "CSQLite3"),
        .target(name: "NFDecoderIPC", linkerSettings: [.linkedLibrary("bsm")]),
        .target(name: "ForensicsCore", dependencies: ["CSQLite3", "NFDecoderIPC"]),
        .target(name: "NFDocumentDecoding", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "NativeForensics", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "NFDocumentDecoder", dependencies: ["ForensicsCore", "NFDocumentDecoding"]),
        .executableTarget(name: "NFDocumentDecoderXPC", dependencies: ["ForensicsCore", "NFDecoderIPC"]),
        .executableTarget(name: "NFDocumentDecoderWorker", dependencies: ["ForensicsCore", "NFDocumentDecoding", "NFDecoderIPC"]),
        .executableTarget(name: "AutopsyUDFExport", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "FilesystemSearchBenchmark", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "ForensicsPipelineBenchmark", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "AssignmentWorkflowProbe", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "MilestoneWorkflowProbe", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "NativeWorkloadProbe", dependencies: ["ForensicsCore"]),
        .executableTarget(name: "CaseHistoryWorkloadProbe", dependencies: ["ForensicsCore"]),
        .testTarget(name: "ForensicsCoreTests", dependencies: ["ForensicsCore", "NFDocumentDecoder", "NFDocumentDecoding", "NFDecoderIPC"]),
        .testTarget(name: "NativeForensicsTests", dependencies: ["NativeForensics", "ForensicsCore"])
    ]
)
