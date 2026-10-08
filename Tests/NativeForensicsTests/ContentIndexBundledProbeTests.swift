import Darwin
import Foundation
import Testing
@testable import NativeForensics

@Suite("ContentIndexBundledProbeTests")
struct ContentIndexBundledProbeTests {
    @Test func argumentsRequireOnlyExplicitAbsoluteSiblingSyntheticLocations() throws {
        let fixture = "/private/tmp/nf-index-fixture-owned.noindex"
        let output = "/private/tmp/nf-index-run-owned.noindex"
        let parsed = try ContentIndexBundledProbe.Arguments.parse(["--output", output, "--fixture", fixture])
        #expect(parsed.fixture.path == fixture); #expect(parsed.output.path == output)
        let rejected = [
            ["--fixture", fixture],
            ["--fixture", fixture, "--fixture", fixture],
            ["--fixture", fixture, "--engine", output],
            ["--fixture", "relative.noindex", "--output", output],
            ["--fixture", fixture, "--output", output + "\0"],
            ["--fixture", "/private/tmp/plain.noindex", "--output", output],
            ["--fixture", fixture, "--output", "/private/other/nf-index-run-owned.noindex"],
            ["--fixture", fixture, "--output", fixture + "/nf-index-run-nested.noindex"],
            ["--fixture", fixture, "--output", "/private/tmp/../tmp/nf-index-run-owned.noindex"]
        ]
        for arguments in rejected {
            #expect(throws: ContentIndexBundledProbe.Failure.arguments) {
                try ContentIndexBundledProbe.Arguments.parse(arguments)
            }
        }
    }

    @Test func ownedOutputCreationRejectsReuseSymlinkAndParentReplacementWithoutCleanup() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let owned = try ContentIndexBundledProbe.OwnedDirectory.open(root)
        defer { owned.close() }
        let candidate = try owned.create("candidate")
        candidate.close()
        let canary = root.appendingPathComponent("candidate/preserve")
        try Data("retain owned prior bytes".utf8).write(to: canary)
        #expect(throws: ContentIndexBundledProbe.Failure.destination) { try owned.create("candidate") }
        #expect(try Data(contentsOf: canary) == Data("retain owned prior bytes".utf8))
        let alias = root.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: root.appendingPathComponent("candidate"))
        #expect(throws: ContentIndexBundledProbe.Failure.destination) { try ContentIndexBundledProbe.OwnedDirectory.open(alias) }
        let moved = root.deletingLastPathComponent().appendingPathComponent(root.lastPathComponent + "-held")
        defer { try? FileManager.default.removeItem(at: moved) }
        try FileManager.default.moveItem(at: root, to: moved)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        let foreign = root.appendingPathComponent("preserve")
        try Data("retain replacement bytes".utf8).write(to: foreign)
        #expect(throws: ContentIndexBundledProbe.Failure.destination) { try owned.check() }
        #expect(try Data(contentsOf: foreign) == Data("retain replacement bytes".utf8))
    }

    @Test func privateDirectoryReadRejectsTraversalOversizeAndNonregularInput() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let owned = try ContentIndexBundledProbe.OwnedDirectory.open(root)
        defer { owned.close() }
        let file = root.appendingPathComponent("input.json")
        try Data("owned payload".utf8).write(to: file)
        #expect(try owned.readBytes("input.json", maximumBytes: 32) == Data("owned payload".utf8))
        #expect(throws: ContentIndexBundledProbe.Failure.fixture) { try owned.readBytes("input.json", maximumBytes: 2) }
        #expect(throws: ContentIndexBundledProbe.Failure.destination) { try owned.readBytes("../outside", maximumBytes: 32) }
        let nested = try owned.create("nested")
        nested.close()
        #expect(throws: ContentIndexBundledProbe.Failure.fixture) { try owned.readBytes("nested", maximumBytes: 32) }
    }

    @Test func observerAcknowledgementIsExactBoundedAndPreservesTheNextLine() throws {
        var descriptors: [Int32] = [0, 0]
        try #require(Darwin.pipe(&descriptors) == 0)
        defer { Darwin.close(descriptors[0]); Darwin.close(descriptors[1]) }
        let payload = Data("ACK 43123\nACK 43124\n".utf8)
        let count = payload.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }
        #expect(count == payload.count)
        #expect(ContentIndexBundledProbe.waitForAcknowledgement(pid: 43123, descriptor: descriptors[0]))
        #expect(ContentIndexBundledProbe.waitForAcknowledgement(pid: 43124, descriptor: descriptors[0]))
    }

    @Test func observerAcknowledgementRefusesWrongPidClosedPipeOversizeAndZeroPid() throws {
        for payload in ["ACK 999\n", String(repeating: "X", count: 64)] {
            var descriptors: [Int32] = [0, 0]
            try #require(Darwin.pipe(&descriptors) == 0)
            let bytes = Data(payload.utf8)
            _ = bytes.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }
            Darwin.close(descriptors[1])
            #expect(!ContentIndexBundledProbe.waitForAcknowledgement(pid: 43123, descriptor: descriptors[0]))
            Darwin.close(descriptors[0])
        }
        var descriptors: [Int32] = [0, 0]
        try #require(Darwin.pipe(&descriptors) == 0)
        Darwin.close(descriptors[1])
        #expect(!ContentIndexBundledProbe.waitForAcknowledgement(pid: 43123, descriptor: descriptors[0]))
        #expect(!ContentIndexBundledProbe.waitForAcknowledgement(pid: 0, descriptor: descriptors[0]))
        Darwin.close(descriptors[0])
    }

    private func directory() throws -> URL {
        let path = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("nf-index-probe-unit-\(UUID().uuidString.lowercased())", isDirectory: true)
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        return path
    }
}
