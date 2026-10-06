import Foundation
import Testing
@testable import ForensicsCore

/// Opt-in tests run the real helper only against a generated manifest marked
/// synthetic. CI may enable these after building the local engine/fixtures.
@Suite("Native engine integration")
struct EngineIntegrationTests {
    @Test("Real helper enumeration, exact bytes and case cache roundtrip", .enabled(if: NativeEngineFixture.available))
    func realHelperRoundtrip() async throws {
        let fixture = try NativeEngineFixture()
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("EngineIntegration-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let client = EngineClient(helperURL: fixture.helper)
        var extractions = 0
        for (index, expected) in fixture.manifest.images.enumerated() {
            let sources = try fixture.paths(for: expected)
            let options = EngineOptions(sectorSize: expected.sectorSize, timezone: "UTC")
            let before = try await ImageInspector.inspect(url: sources[0], progress: { _ in })
            let result = try await client.enumerate(imagePaths: sources, options: options)
            #expect(result.status == .completed)
            #expect(result.image.logicalSha256 == expected.logicalSha256)
            #expect(result.image.logicalSize == expected.logicalSize)
            #expect(result.image.sectorSize == expected.sectorSize)
            #expect(result.sourcePaths == sources.map(\.path))
            #expect(result.sourceFileHashes.count == sources.count)
            #expect(result.volumes.contains(where: { $0.offsetBytes == expected.fsOffsetBytes }))
            let payloadPaths = result.files.filter { !$0.isDirectory && !$0.name.hasPrefix("$") && $0.name != "NFTK (Volume Label Entry)" }
            #expect(payloadPaths.count == expected.files.count)
            #expect(Set(payloadPaths.map { $0.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")) }) == Set(expected.files.map(\.path)))
            #expect(Set(result.files.map(\.id)).count == result.files.count)
            let originalCase = try CaseStore.create(name: "Synthetic image \(index)", in: temporary)
            let forensicCase = try CaseStore.adding(image: before, to: originalCase)
            let evidenceID = try #require(forensicCase.manifest.evidence.first?.id)
            let manifestBefore = try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent("manifest.json"))
            try EngineResultStore.save(result: result, evidenceID: evidenceID, in: forensicCase.bundleURL)
            let reopened = try #require(try EngineResultStore.load(evidenceID: evidenceID, in: forensicCase.bundleURL))
            #expect(reopened.files == result.files)
            #expect(reopened.sourceFileHashes == result.sourceFileHashes)
            #expect(try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent("manifest.json")) == manifestBefore)
            for expectedFile in expected.files {
                let file = try #require(result.files.first(where: { $0.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")) == expectedFile.path }))
                #expect(file.size == expectedFile.size)
                #expect(file.isDeleted == expectedFile.isDeleted)
                try checkTimestamps(file, expectedFile: expectedFile, image: expected, timezone: "UTC")
                if let attributeType = expectedFile.attributeType { #expect(file.attributeType == attributeType) }
                if let attributeID = expectedFile.attributeID { #expect(file.attributeID == attributeID) }
                if let metaAddress = expectedFile.metaAddress { #expect(file.metaAddress == metaAddress) }
                let output = temporary.appendingPathComponent("Export-\(UUID().uuidString).bin")
                var extractionOptions = options
                extractionOptions.hashLogicalImage = false
                let receipt = try await client.extract(imagePaths: sources, file: file, outputURL: output, options: extractionOptions, expectedSourceHashes: reopened.sourceFileHashes)
                #expect(receipt.byteCount == expectedFile.size)
                #expect(receipt.sha256 == expectedFile.sha256)
                #expect(try Data(contentsOf: output) == expectedFile.bytes)
                extractions += 1
            }
            for path in sources {
                let after = try await ImageInspector.inspect(url: path, progress: { _ in })
                #expect(after.sha256 == result.sourceFileHashes[path.path])
            }
        }
        #expect(extractions == fixture.manifest.images.reduce(0, { $0 + $1.files.count }))
    }

    @Test("Real timestamp matrix preserves offsets, precision and missing values", .enabled(if: NativeEngineFixture.available))
    func realTimestampMatrix() async throws {
        let fixture = try NativeEngineFixture()
        let client = EngineClient(helperURL: fixture.helper)
        for image in fixture.manifest.images {
            for timezone in image.timestampMatrix?.requestTimezones ?? [] where timezone != "UTC" {
                let result = try await client.enumerate(imagePaths: fixture.paths(for: image), options: EngineOptions(sectorSize: image.sectorSize, timezone: timezone, hashLogicalImage: false))
                #expect(result.status == .completed)
                for expectedFile in image.files {
                    let file = try #require(result.files.first(where: { $0.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")) == expectedFile.path }))
                    try checkTimestamps(file, expectedFile: expectedFile, image: image, timezone: timezone)
                }
            }
        }
    }

    private func checkTimestamps(_ file: FilesystemEntry, expectedFile: NativeFixtureFile, image: NativeFixtureImage, timezone: String) throws {
        let timestamps: [String: Int64]
        if let matrix = expectedFile.timestampsByTimezone {
            timestamps = try #require(matrix[timezone])
        } else {
            let epoch = image.expectedEpochUTC - (timezone == "Asia/Bangkok" && image.validUTCOffset != true ? 7 * 3600 : 0)
            timestamps = ["createdEpoch": epoch, "modifiedEpoch": epoch,
                          "accessedEpoch": image.validUTCOffset == true ? epoch : epoch - 80000,
                          "createdNanoseconds": Int64(image.expectedCreatedNanoseconds ?? 0),
                          "modifiedNanoseconds": Int64(image.expectedModifiedNanoseconds ?? 0)]
        }
        let actual: [(String, Int64?, Int32)] = [
            ("created", file.createdEpoch, file.createdNanoseconds),
            ("modified", file.modifiedEpoch, file.modifiedNanoseconds),
            ("accessed", file.accessedEpoch, file.accessedNanoseconds),
            ("changed", file.changedEpoch, file.changedNanoseconds),
        ]
        for (prefix, epoch, nanoseconds) in actual {
            #expect(epoch == timestamps[prefix + "Epoch"], "\(expectedFile.path) \(timezone) \(prefix)")
            #expect(Int64(nanoseconds) == (timestamps[prefix + "Nanoseconds"] ?? 0))
        }
    }

    @Test("Real inspect accepts volume metadata without silently enumerating files", .enabled(if: NativeEngineFixture.available))
    func realInspect() async throws {
        let fixture = try NativeEngineFixture()
        let first = try #require(fixture.manifest.images.first)
        let result = try await EngineClient(helperURL: fixture.helper).inspect(imagePaths: fixture.paths(for: first), options: EngineOptions(sectorSize: first.sectorSize, timezone: "UTC"))
        #expect(result.logicalSha256 == first.logicalSha256)
        #expect(result.logicalSize == first.logicalSize)
    }

    @Test("Real enumeration file limit remains explicitly partial", .enabled(if: NativeEngineFixture.available))
    func realPartial() async throws {
        let fixture = try NativeEngineFixture()
        let first = try #require(fixture.manifest.images.first)
        let result = try await EngineClient(helperURL: fixture.helper).enumerate(imagePaths: fixture.paths(for: first), options: EngineOptions(sectorSize: first.sectorSize, timezone: "UTC", maxFiles: 1))
        #expect(result.status == .partial)
        #expect(result.files.count == 1)
        #expect(!result.warnings.isEmpty)
    }
}

private struct NativeEngineFixture {
    static var available: Bool {
        ProcessInfo.processInfo.environment["NFTSK_ENGINE_HELPER"] != nil && ProcessInfo.processInfo.environment["NFTSK_SYNTHETIC_FIXTURES"] != nil
    }
    let helper: URL
    let directory: URL
    let manifest: NativeFixtureManifest

    init() throws {
        let environment = ProcessInfo.processInfo.environment
        helper = URL(fileURLWithPath: try #require(environment["NFTSK_ENGINE_HELPER"]))
        directory = URL(fileURLWithPath: try #require(environment["NFTSK_SYNTHETIC_FIXTURES"])).resolvingSymlinksInPath()
        manifest = try JSONDecoder().decode(NativeFixtureManifest.self, from: Data(contentsOf: directory.appendingPathComponent("manifest.json")))
        // Schema 3 adds independent per-entry timestamp and stream expectations.
        try #require(manifest.synthetic && [1, 2, 3].contains(manifest.schemaVersion) && !manifest.images.isEmpty)
    }

    func paths(for image: NativeFixtureImage) throws -> [URL] {
        try (image.imagePaths ?? [image.path]).map { path in
            let url = directory.appendingPathComponent(path).resolvingSymlinksInPath()
            try #require(!path.hasPrefix("/") && FileAccess.isInside(url, directory: directory))
            return url
        }
    }
}

private struct NativeFixtureManifest: Decodable {
    let schemaVersion: Int
    let synthetic: Bool
    let images: [NativeFixtureImage]
}

private struct NativeFixtureImage: Decodable {
    let path: String
    let imagePaths: [String]?
    let sectorSize: Int
    let fsOffsetBytes: Int64
    let logicalSize: Int64
    let logicalSha256: String
    let expectedEpochUTC: Int64
    let expectedCreatedNanoseconds: Int32?
    let expectedModifiedNanoseconds: Int32?
    let validUTCOffset: Bool?
    let timestampMatrix: NativeFixtureTimestampMatrix?
    let files: [NativeFixtureFile]
}

private struct NativeFixtureTimestampMatrix: Decodable {
    let requestTimezones: [String]
}

private struct NativeFixtureFile: Decodable {
    let path: String
    let size: Int64
    let sha256: String
    let isDeleted: Bool
    let payloadHex: String
    let timestampsByTimezone: [String: [String: Int64]]?
    let attributeType: Int32?
    let attributeID: Int32?
    let metaAddress: UInt64?
    var bytes: Data {
        let characters = Array(payloadHex.utf8)
        func nibble(_ character: UInt8) -> UInt8 { character <= 57 ? character - 48 : character - 87 }
        return Data(stride(from: 0, to: characters.count, by: 2).map { nibble(characters[$0]) * 16 + nibble(characters[$0 + 1]) })
    }
}
