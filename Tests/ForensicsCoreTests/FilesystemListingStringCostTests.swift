import Foundation
import Testing
@testable import ForensicsCore

struct FilesystemListingStringCostTests {
    @Test("All stored header, provenance and recovery strings contribute exactly once")
    func allStoredFields() throws {
        let result = try fixture(includeOptionalFields: true)
        let measured = try FilesystemListingStringCost.measure(result)
        // Independent arithmetic: versions 8, four stored source paths 52,
        // two hashes 128, options/image types and zone 9, volume 4,
        // file/recovery 17, three timestamp civil/zone pairs 32, warning 1.
        #expect(measured.rawUTF8Bytes == 251)
        let encoder = JSONEncoder()
        #expect(try encoder.encode(result).count > measured.rawUTF8Bytes)
    }

    @Test("Absent optional fields contribute zero and enums contribute no stored String payload")
    func absentOptionalFields() throws {
        #expect(try FilesystemListingStringCost.measure(fixture()).rawUTF8Bytes == 116)
    }

    @Test("Thai and decomposed combining text are measured by original UTF-8 bytes")
    func exactUnicodeBytes() throws {
        let file = entry(path: "/ไทย", name: "e\u{301}")
        #expect(file.path.utf8.count == 10)
        #expect(file.name.count == 1 && file.name.utf8.count == 3)
        #expect(try FilesystemListingStringCost.measure(fixture(files: [file])).rawUTF8Bytes == 126)
    }

    @Test("UTF-8 field bounds reject an overlong Thai path even when its character count is smaller")
    func unicodeValidationBound() throws {
        let accepted = String(repeating: "ก", count: 10_922) + "ab"
        #expect(accepted.utf8.count == 32_768)
        _ = try FilesystemListingStringCost.measure(fixture(files: [entry(path: accepted)]))
        let rejected = String(repeating: "ก", count: 10_923)
        #expect(rejected.count < 32_768 && rejected.utf8.count == 32_769)
        #expect(throws: (any Error).self) {
            try FilesystemListingStringCost.measure(fixture(files: [entry(path: rejected)]))
        }
    }

    @Test("Canonically equivalent image paths still have their own UTF-8 field bound")
    func equivalentScopedPaths() throws {
        let composed = "/" + String(repeating: "é", count: 16_383)
        let decomposed = "/" + String(repeating: "e\u{301}", count: 16_383)
        #expect(composed == decomposed)
        #expect(composed.utf8.count == 32_767 && decomposed.utf8.count == 49_150)
        let hash = String(repeating: "a", count: 64)
        let result = EnumerationResult(engineVersion: "eng", patchDigest: "patch", sourcePaths: [composed],
            sourceFileHashes: [composed: hash], options: .init(hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: 0, sectorSize: 512, imagePaths: [decomposed]),
            volumes: [], files: [], warnings: [], status: .completed)
        #expect(throws: EngineError.invalidCache("A stored filesystem source path exceeds its UTF-8 bounds.")) {
            try FilesystemListingStringCost.measure(result)
        }
    }

    @Test("An aggregate over 64 MiB stops despite every individual row being within its bounds")
    func aggregateMeasurementBound() throws {
        // The repeated fields share test storage. Their logical retained String
        // payload is still charged per occurrence, without creating huge inputs.
        let text = String(repeating: "a", count: 32_768)
        let files = (0..<1_025).map { entry(id: "f\($0)", path: text, name: text) }
        #expect(files.count < 50_000 && files[0].path.utf8.count == 32_768)
        #expect(throws: EngineError.limitExceeded("The filesystem listing String payload exceeds 64 MiB.")) {
            try FilesystemListingStringCost.measure(fixture(files: files))
        }
    }

    @Test("Validation rejects original file counts, duplicate IDs and nested provenance bounds")
    func strictValidation() throws {
        #expect(throws: (any Error).self) {
            try FilesystemListingStringCost.measure(fixture(files: [entry(), entry(id: "other")], maximumFiles: 1))
        }
        #expect(throws: (any Error).self) {
            try FilesystemListingStringCost.measure(fixture(files: [entry(), entry()]))
        }
        #expect(throws: (any Error).self) {
            try FilesystemListingStringCost.measure(fixture(files: Array(repeating: entry(), count: 50_001)))
        }
        let oversizedWarning = FilesystemEntry(id: "f", path: "/x", name: "x", fsOffsetBytes: 0,
            metaAddress: 1, size: 0, isDirectory: false, isDeleted: false,
            recoveryWarnings: [String(repeating: "a", count: 4_097)])
        #expect(throws: (any Error).self) {
            try FilesystemListingStringCost.measure(fixture(files: [oversizedWarning]))
        }
        let invalidTimestamp = FilesystemCivilTimestamp(rawDate: 0, rawTime: 0, civil: "civil", status: .assumedZone,
            timezone: "UTC", candidateEpochs: [0, 1, 2], precisionNanoseconds: 1)
        let invalidFile = FilesystemEntry(id: "f", path: "/x", name: "x", fsOffsetBytes: 0,
            metaAddress: 1, size: 0, isDirectory: false, isDeleted: false,
            timestampProvenance: .init(created: invalidTimestamp))
        #expect(throws: (any Error).self) {
            try FilesystemListingStringCost.measure(fixture(files: [invalidFile]))
        }
    }

    @Test("Oversized header arrays are rejected before header validation allocates their projections")
    func headerCountBounds() throws {
        let original = try fixture(includeOptionalFields: true)
        let identity = try #require(original.sourceIdentities.first)
        let oversized = replacingHeader(original, sourceIdentities: Array(repeating: identity, count: 1_025))
        #expect(throws: (any Error).self) { try FilesystemListingStringCost.measure(oversized) }
        let warnings = replacingHeader(original, warnings: Array(repeating: "w", count: 1_025))
        #expect(throws: (any Error).self) { try FilesystemListingStringCost.measure(warnings) }
    }

    @Test("Checked accounting rejects negative input and integer overflow")
    func checkedArithmetic() throws {
        #expect(try FilesystemListingStringCost.checkedTotal(Int.max - 1, adding: 1) == Int.max)
        #expect(throws: (any Error).self) { try FilesystemListingStringCost.checkedTotal(Int.max, adding: 1) }
        #expect(throws: (any Error).self) { try FilesystemListingStringCost(rawUTF8Bytes: -1) }
        #expect(throws: (any Error).self) { try FilesystemListingStringCost.checkedTotal(0, adding: -1) }
    }

    @Test("Cancellation is checked before work and during a listing larger than 128 rows")
    func cancellationCheckpoints() throws {
        #expect(throws: CancellationError.self) {
            try FilesystemListingStringCost.measure(fixture(), checkCancellation: { throw CancellationError() })
        }
        let result = try fixture(files: (0..<300).map { entry(id: "f\($0)") })
        var checkpoints = 0
        #expect(throws: CancellationError.self) {
            try FilesystemListingStringCost.measure(result, checkCancellation: {
                checkpoints += 1
                if checkpoints == 6 { throw CancellationError() }
            })
        }
        #expect(checkpoints == 6)
    }

    @Test("An already canceled worker cannot publish a cost for even an empty listing")
    func actualTaskCancellation() async throws {
        let result = try fixture(files: [])
        let task = Task.detached {
            withUnsafeCurrentTask { $0?.cancel() }
            return try FilesystemListingStringCost.measure(result)
        }
        do {
            _ = try await task.value
            Issue.record("A canceled worker returned a listing cost.")
        } catch is CancellationError {
            // Expected: this proves the public entry point consults task cancellation.
        }
    }

    private func entry(id: String = "f", path: String = "/x", name: String = "x") -> FilesystemEntry {
        FilesystemEntry(id: id, path: path, name: name, fsOffsetBytes: 0, metaAddress: 1,
            size: 0, isDirectory: false, isDeleted: false)
    }

    private func fixture(includeOptionalFields: Bool = false, files: [FilesystemEntry]? = nil,
                         maximumFiles: Int = 50_000) throws -> EnumerationResult {
        let source = "/synthetic.dd", hash = String(repeating: "a", count: 64)
        var identities: [EngineSourceIdentity] = []
        var file = entry()
        if includeOptionalFields {
            let data = Data("""
                {"path":"/synthetic.dd","device":1,"inode":1,"size":0,"modifiedSeconds":0,
                 "modifiedNanoseconds":0,"changedSeconds":0,"changedNanoseconds":0}
                """.utf8)
            identities = [try JSONDecoder().decode(EngineSourceIdentity.self, from: data)]
            let created = FilesystemCivilTimestamp(rawDate: 0, rawTime: 0, civil: "created", status: .assumedZone,
                timezone: "UTC", candidateEpochs: [0], precisionNanoseconds: 1)
            let modified = FilesystemCivilTimestamp(rawDate: 0, rawTime: 0, civil: "modified", status: .recordedOffset,
                timezone: "UTC", utcOffsetMinutes: 0, candidateEpochs: [1], precisionNanoseconds: 1)
            let accessed = FilesystemCivilTimestamp(rawDate: 0, rawTime: 0, civil: "accessed", status: .nonexistentLocalTime,
                timezone: "UTC", precisionNanoseconds: 1)
            file = FilesystemEntry(id: "f", path: "/x", name: "x", fsOffsetBytes: 0, metaAddress: 1,
                size: 0, isDirectory: false, isDeleted: false, createdEpoch: 0, modifiedEpoch: 1,
                timestampProvenance: .init(created: created, modified: modified, accessed: accessed),
                recoveryStatus: "recoverable", recoveryWarnings: ["rw"])
        }
        return EnumerationResult(engineVersion: "eng", patchDigest: "patch", sourcePaths: [source],
            sourceIdentities: identities, sourceFileHashes: [source: hash],
            options: .init(imageType: "raw", timezone: "UTC", maxFiles: maximumFiles, hashLogicalImage: includeOptionalFields),
            image: .init(imageType: "raw", logicalSize: 0, sectorSize: 512,
                logicalSha256: includeOptionalFields ? hash : nil, imagePaths: includeOptionalFields ? [source] : nil),
            volumes: [.init(id: "v", offsetBytes: 0, filesystem: "FAT", blockSize: 512, blockCount: 0)],
            files: files ?? [file], warnings: ["w"], status: .partial, savedAt: Date(timeIntervalSince1970: 0))
    }

    private func replacingHeader(_ result: EnumerationResult, sourceIdentities: [EngineSourceIdentity]? = nil,
                                 warnings: [String]? = nil) -> EnumerationResult {
        EnumerationResult(schemaVersion: result.schemaVersion, engineVersion: result.engineVersion,
            patchDigest: result.patchDigest, sourcePaths: result.sourcePaths,
            sourceIdentities: sourceIdentities ?? result.sourceIdentities, sourceFileHashes: result.sourceFileHashes,
            options: result.options, image: result.image, volumes: result.volumes, files: result.files,
            warnings: warnings ?? result.warnings, status: result.status, savedAt: result.savedAt)
    }
}
