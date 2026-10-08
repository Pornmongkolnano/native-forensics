import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

struct DocumentClientTests {
    @Test func previewDefaultObserverPreservesActualClientResultAndSource() async throws {
        let fixture = try DocumentMockFixture()
        defer { fixture.remove() }
        let service = FilesystemDocumentPreviewService(engine: EngineClient(helperURL: fixture.helper), documents: fixture.client)
        let result = try await service.analyzeDocument(fixture.input)
        #expect(result.status == .decoded)
        #expect(result.textPages.first?.text == "trusted fixture")
        #expect(result.sourceSHA256 == fixture.input.expectedSHA256)
        #expect(try Data(contentsOf: fixture.source) == Data("trusted fixture".utf8))
    }

    @Test func previewObserverForwardsActualStartedAndExitedOwnerEvents() async throws {
        let fixture = try DocumentMockFixture()
        defer { fixture.remove() }
        let events = DocumentLifecycleFixtureEvents()
        let service = FilesystemDocumentPreviewService(engine: EngineClient(helperURL: fixture.helper), documents: fixture.client,
            decoderLifecycle: events.record)
        let result = try await service.analyzeDocument(fixture.input)
        let recorded = events.snapshot
        #expect(result.status == .decoded)
        #expect(recorded.count == 2)
        guard let first = recorded.first, let last = recorded.last,
              case .started(let startedPID, let backend) = first,
              case .exited(let exitedPID) = last else { Issue.record("Actual lifecycle sequence missing"); return }
        #expect(backend == .developmentSeatbelt)
        #expect(startedPID == exitedPID)
        #expect(Darwin.kill(startedPID, 0) == -1 && errno == ESRCH)
    }

    @Test func timeoutLifecycleReportsExitedOnlyAfterTheOwnedChildWasReaped() async throws {
        let fixture = try DocumentMockFixture(hang: true)
        defer { fixture.remove() }
        let events = DocumentLifecycleFixtureEvents()
        let client = DocumentAnalysisClient(helperURL: fixture.helper, timeout: 0.25, sandboxPolicy: .disabledForTesting)
        await #expect(throws: DocumentAnalysisError.timeout) { try await client.analyze(fixture.input, lifecycle: events.record) }
        let values = events.snapshot
        guard values.count == 2, case .started(let pid, _) = values[0], case .exited(let exited) = values[1] else {
            Issue.record("Timeout lifecycle lacked positive owned reap"); return
        }
        #expect(pid == exited); #expect(Darwin.kill(pid, 0) == -1 && errno == ESRCH)
    }

    @Test func cancellationLifecycleWaitsForItsActuallyStartedOwnedChild() async throws {
        let fixture = try DocumentMockFixture(hang: true)
        defer { fixture.remove() }
        let events = DocumentLifecycleFixtureEvents()
        let (stream, continuation) = AsyncStream<Int32>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let client = fixture.client
        let task = Task {
            defer { continuation.finish() }
            return try await client.analyze(fixture.input, lifecycle: { event in
                events.record(event)
                if case .started(let pid, _) = event { continuation.yield(pid) }
            })
        }
        var iterator = stream.makeAsyncIterator()
        guard let pid = await iterator.next() else { _ = try await task.value; Issue.record("No owned child"); return }
        task.cancel()
        do { _ = try await task.value; Issue.record("Cancellation returned a result") }
        catch { #expect(error is CancellationError) }
        let values = events.snapshot
        guard values.count == 2, case .exited(let exited) = values[1] else { Issue.record("Cancelled child was not reaped"); return }
        #expect(pid == exited); #expect(Darwin.kill(pid, 0) == -1 && errno == ESRCH)
    }
    @Test func inputSizeHashAndNoFollowAreVerifiedBeforeLaunch() async throws {
        let fixture = try DocumentMockFixture()
        defer { fixture.remove() }
        let wrong = DocumentInput(fileURL: fixture.source, expectedSHA256: String(repeating: "f", count: 64), expectedByteCount: fixture.input.expectedByteCount)
        await #expect(throws: DocumentAnalysisError.integrityMismatch) { try await fixture.client.analyze(wrong) }
        let alias = fixture.root.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: fixture.source)
        let linked = DocumentInput(fileURL: alias, expectedSHA256: fixture.input.expectedSHA256, expectedByteCount: fixture.input.expectedByteCount)
        await #expect(throws: DocumentAnalysisError.invalidInput) { try await fixture.client.analyze(linked) }
        let directory = DocumentInput(fileURL: fixture.root, expectedSHA256: fixture.input.expectedSHA256, expectedByteCount: fixture.input.expectedByteCount)
        await #expect(throws: DocumentAnalysisError.invalidInput) { try await fixture.client.analyze(directory) }
        #expect(!FileManager.default.fileExists(atPath: fixture.marker.path))
    }

    @Test func validResponseIsBoundToCompleteSourceReceipt() async throws {
        let fixture = try DocumentMockFixture()
        defer { fixture.remove() }
        let analysis = try await fixture.client.analyze(fixture.input)
        #expect(analysis.status == .decoded)
        #expect(analysis.schemaVersion == 2)
        let provenance = try #require(analysis.provenance)
        #expect(provenance.isolation == .testFixture)
        #expect(provenance.decoderExecutableSHA256 == SHA256.hash(data: try Data(contentsOf: fixture.helper)).map { String(format: "%02x", $0) }.joined())
        #expect(provenance.derivedTextSHA256 == (try CaseWorkCoding.digest(analysis.textPages)))
        #expect(analysis.sourceSHA256 == fixture.input.expectedSHA256)
        #expect(analysis.textPages.first?.text == "trusted fixture")
        #expect(try Data(contentsOf: fixture.source) == Data("trusted fixture".utf8))
    }

    @Test func helperResponseCannotImpersonateAnotherFile() async throws {
        let fixture = try DocumentMockFixture(responseHash: String(repeating: "f", count: 64))
        defer { fixture.remove() }
        await #expect(throws: DocumentAnalysisError.invalidResponse) { try await fixture.client.analyze(fixture.input) }
    }

    @Test func postDecodeSourceMutationFailsClosed() async throws {
        let fixture = try DocumentMockFixture(mutation: true)
        defer { fixture.remove() }
        do { _ = try await fixture.client.analyze(fixture.input); Issue.record("Mutated source was accepted.") }
        catch { #expect(error as? DocumentAnalysisError == .sourceChanged || error as? DocumentAnalysisError == .integrityMismatch) }
    }

    @Test func timeoutReapsTheActuallyStartedOwnedChild() async throws {
        let fixture = try DocumentMockFixture(hang: true)
        defer { fixture.remove() }
        let (stream, continuation) = AsyncStream<Int32>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let work = Task {
            defer { continuation.finish() }
            return try await DocumentAnalysisClient(helperURL: fixture.helper, timeout: 1, sandboxPolicy: .disabledForTesting).analyze(fixture.input,
                started: { continuation.yield($0) })
        }
        var iterator = stream.makeAsyncIterator()
        guard let pid = await iterator.next() else {
            _ = try await work.value
            Issue.record("No owned child started.")
            return
        }
        await #expect(throws: DocumentAnalysisError.timeout) {
            try await work.value
        }
        #expect(Darwin.kill(pid, 0) == -1 && errno == ESRCH)
    }

    @Test func callerCancellationAfterOwnershipWinsAndReapsChild() async throws {
        let fixture = try DocumentMockFixture(customScript: "/bin/echo '{bad-response}'")
        defer { fixture.remove() }
        let gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        let (stream, continuation) = AsyncStream<Int32>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let work = Task {
            defer { continuation.finish() }
            return try await DocumentAnalysisClient(helperURL: fixture.helper, sandboxPolicy: .disabledForTesting).analyze(fixture.input, started: { pid in
                continuation.yield(pid)
                // Hold the owned worker at a known boundary until this test
                // explicitly cancels its caller. No poll/sleep guesses and no
                // relaxed deadline or weakened accepted error are involved.
                gate.wait()
            })
        }
        var iterator = stream.makeAsyncIterator()
        guard let pid = await iterator.next() else {
            _ = try await work.value
            Issue.record("No owned child started.")
            return
        }
        work.cancel()
        gate.signal()
        do { _ = try await work.value; Issue.record("Cancelled inspection returned a result.") }
        catch { #expect(error is CancellationError) }
        #expect(Darwin.kill(pid, 0) == -1 && errno == ESRCH)
    }

    @Test func outputFloodAndMalformedJSONAreRejected() async throws {
        let fixture = try DocumentMockFixture(customScript: "while :; do printf '%8192s' ' '; done")
        defer { fixture.remove() }
        await #expect(throws: DocumentAnalysisError.outputLimit) { try await fixture.client.analyze(fixture.input) }
        let invalid = try DocumentMockFixture(customScript: "/bin/echo '{invalid}'")
        defer { invalid.remove() }
        await #expect(throws: DocumentAnalysisError.invalidResponse) { try await invalid.client.analyze(invalid.input) }
    }
}

private final class DocumentLifecycleFixtureEvents: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [DocumentDecoderLifecycleEvent] = []
    var snapshot: [DocumentDecoderLifecycleEvent] { lock.withLock { events } }
    func record(_ event: DocumentDecoderLifecycleEvent) { lock.withLock { events.append(event) } }
}

private struct DocumentMockFixture {
    let root: URL, source: URL, helper: URL, marker: URL
    let input: DocumentInput
    var client: DocumentAnalysisClient { DocumentAnalysisClient(helperURL: helper, timeout: 2, sandboxPolicy: .disabledForTesting) }

    init(responseHash: String? = nil, mutation: Bool = false, hang: Bool = false, customScript: String? = nil) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("nf-document-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        source = root.appendingPathComponent("file.txt"); helper = root.appendingPathComponent("helper"); marker = root.appendingPathComponent("pid")
        let bytes = Data("trusted fixture".utf8)
        try bytes.write(to: source)
        input = DocumentInput(fileURL: source, expectedSHA256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(), expectedByteCount: Int64(bytes.count))
        let response = DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
            sourceSHA256: responseHash ?? input.expectedSHA256, sourceByteCount: Int64(bytes.count),
            textPages: [DocumentTextPage(pageNumber: 1, text: "trusted fixture")])
        let json = String(decoding: try JSONEncoder().encode(response), as: UTF8.self)
        func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        var script = "#!/bin/sh\n/bin/cat >/dev/null\n/bin/echo $$ > \(quote(marker.path))\n"
        if hang { script += "/bin/sleep 20\n" }
        if mutation { script += "/bin/echo changed > \(quote(source.path))\n" }
        script += customScript ?? "/bin/echo \(quote(json))"
        try Data(script.utf8).write(to: helper)
        guard Darwin.chmod(helper.path, 0o700) == 0 else { throw DocumentAnalysisError.launchFailed }
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
