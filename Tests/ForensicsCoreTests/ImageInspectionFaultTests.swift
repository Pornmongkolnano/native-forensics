import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("ImageInspectionFaultTests", .serialized)
struct ImageInspectionFaultTests {
    @Test("The existing multi-chunk recipe agrees with the retained external shasum receipt")
    func independentMultichunkHash() async throws {
        let fixture = try InspectionFaultFixture(); defer { fixture.remove() }
        let before = try FileAccess.identity(at: fixture.source), probe = InspectionReadProbe()
        let image = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        #expect(image.byteCount == 3_145_745)
        #expect(image.sha256 == "69112280f593fd44684d97d3fe42cdcb84da4ae495d8e1db649f06c3596a7ce6")
        #expect(image.hashScope == FileHashScope.selectedFileBytes)
        #expect(image.sourceIdentity == before)
        #expect(try FileAccess.identity(at: fixture.source) == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.bytes)
        // Also prove the internal observational seam retains the public hash.
        let observed = try await ImageInspector.inspect(url: fixture.source, progress: { probe.progress($0) },
            readForTesting: { descriptor, buffer, requested in
                let offset = Darwin.lseek(descriptor, 0, SEEK_CUR)
                let count = try FileAccess.read(descriptor, into: buffer, count: requested)
                probe.read(descriptor: descriptor, offset: offset, requested: requested, bytes: buffer, count: count)
                return count
            }, descriptorClosedForTesting: { probe.closed($0, $1) })
        #expect(observed.sha256 == image.sha256)
        #expect(probe.reads.count >= 4)
        #expect(probe.reads.reduce(0) { $0 + $1.count } == 3_145_745)
        #expect(probe.reads.first?.offset == 0)
        #expect(probe.reads.allSatisfy { $0.count > 0 && $0.count <= $0.requested && $0.requested <= 1_048_576 })
        #expect(zip(probe.reads, probe.reads.dropFirst()).allSatisfy { $0.offset + off_t($0.count) == $1.offset })
        let lastRead = try #require(probe.reads.last)
        #expect(lastRead.offset + off_t(lastRead.count) == 3_145_745)
        #expect(probe.closes.count == 1); #expect(probe.closes.first?.status == 0)
        #expect(probe.closes.first?.descriptor == probe.reads.first?.descriptor)
        #expect(probe.reads.allSatisfy { $0.flags >= 0 && ($0.flags & O_ACCMODE) == O_RDONLY })
    }

    @Test("A real first chunk followed by mid-read EIO publishes no partial hash and closes its owned descriptor")
    func midReadEIO() async throws {
        let fixture = try InspectionFaultFixture(); defer { fixture.remove() }
        let before = try FileAccess.identity(at: fixture.source), probe = InspectionReadProbe()
        var sawEIO = false
        do {
            _ = try await ImageInspector.inspect(url: fixture.source, progress: { probe.progress($0) },
                readForTesting: { descriptor, buffer, requested in
                    let offset = Darwin.lseek(descriptor, 0, SEEK_CUR)
                    if offset == 1_048_576 {
                        probe.read(descriptor: descriptor, offset: offset, requested: requested, bytes: buffer, count: 0)
                        errno = EIO
                        throw FileAccess.posixError("Cannot read file")
                    }
                    let count = try FileAccess.read(descriptor, into: buffer, count: min(requested, Int(1_048_576 - offset)))
                    probe.read(descriptor: descriptor, offset: offset, requested: requested, bytes: buffer, count: count)
                    return count
                }, descriptorClosedForTesting: { probe.closed($0, $1) })
            probe.published()
            Issue.record("Mid-read EIO must reject inspection before publishing an InspectedImage.")
        } catch let error as ForensicsError {
            if case .io(let detail) = error {
                sawEIO = detail.hasSuffix("(5).")
                #expect(detail.hasPrefix("Cannot read file:"))
            } else { Issue.record("Expected a read I/O failure, received \(error).") }
        }
        #expect(sawEIO); #expect(!probe.didPublish)
        let reads = probe.reads
        #expect(reads.count >= 2)
        #expect(reads.filter { $0.count > 0 }.reduce(0) { $0 + $1.count } == 1_048_576)
        #expect((reads.first?.count ?? 0) > 0)
        #expect(reads.last?.offset == 1_048_576)
        #expect(reads.last?.requested == 1_048_576)
        #expect(probe.prefix == Data(fixture.bytes.prefix(1_048_576)))
        #expect(probe.closes.count == 1); #expect(probe.closes.first?.status == 0)
        #expect(probe.closes.first?.descriptor == reads.first?.descriptor)
        #expect(reads.allSatisfy { $0.flags >= 0 && ($0.flags & O_ACCMODE) == O_RDONLY })
        #expect(probe.updates.allSatisfy { $0.bytesRead < 3_145_745 && $0.fraction < 1 })
        #expect(try FileAccess.identity(at: fixture.source) == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.bytes)
    }

    @Test("Parent cancellation waits for the active read owner to unwind and close before returning")
    func cancellationDrainsReadOwner() async throws {
        let fixture = try InspectionFaultFixture(); defer { fixture.remove() }
        let before = try FileAccess.identity(at: fixture.source), probe = InspectionReadProbe(), gate = InspectionReadGate()
        let task = Task {
            defer { probe.returned(); gate.inspectionFinished() }
            let result = try await ImageInspector.inspect(url: fixture.source, progress: { probe.progress($0) },
                readForTesting: { descriptor, buffer, requested in
                    let offset = Darwin.lseek(descriptor, 0, SEEK_CUR)
                    if offset == 1_048_576 {
                        probe.read(descriptor: descriptor, offset: offset, requested: requested, bytes: buffer, count: 0)
                        try gate.enterAndWait()
                        try Task.checkCancellation()
                    }
                    let count = try FileAccess.read(descriptor, into: buffer, count: min(requested, Int(1_048_576 - offset)))
                    probe.read(descriptor: descriptor, offset: offset, requested: requested, bytes: buffer, count: count)
                    return count
                }, descriptorClosedForTesting: { probe.closed($0, $1) })
            probe.published(); return result
        }
        do { try await gate.waitUntilEntered() }
        catch {
            task.cancel(); gate.release(); _ = try? await task.value
            throw error
        }
        task.cancel()
        #expect(!probe.didReturn); #expect(probe.closes.isEmpty)
        gate.release()
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(probe.didReturn); #expect(!probe.didPublish)
        #expect(probe.reads.count >= 2)
        #expect(probe.reads.filter { $0.count > 0 }.reduce(0) { $0 + $1.count } == 1_048_576)
        #expect(probe.prefix == Data(fixture.bytes.prefix(1_048_576)))
        #expect(probe.closes.count == 1); #expect(probe.closes.first?.status == 0)
        #expect(probe.closes.first?.descriptor == probe.reads.first?.descriptor)
        #expect(probe.reads.allSatisfy { $0.flags >= 0 && ($0.flags & O_ACCMODE) == O_RDONLY })
        #expect(probe.updates.allSatisfy { $0.bytesRead < 3_145_745 && $0.fraction < 1 })
        #expect(try FileAccess.identity(at: fixture.source) == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.bytes)
    }
}

private struct InspectionFaultFixture: Sendable {
    let folder: URL
    let source: URL
    let bytes: Data
    init() throws {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent("native-inspection-fault-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        var body = Data()
        let pattern = Data((0...255).map(UInt8.init))
        for _ in 0..<12_288 { body.append(pattern) }
        body.append(contentsOf: (0..<17).map(UInt8.init))
        bytes = body; source = folder.appendingPathComponent("large-pattern.dd")
        try bytes.write(to: source, options: .withoutOverwriting)
    }
    func remove() { try? FileManager.default.removeItem(at: folder) }
}

private final class InspectionReadProbe: @unchecked Sendable {
    struct Read: Sendable {
        let descriptor: Int32
        let offset: off_t
        let requested: Int
        let count: Int
        let flags: Int32
    }
    struct Close: Sendable { let descriptor: Int32; let status: Int32 }
    private let lock = NSLock()
    private var readValues: [Read] = [], closeValues: [Close] = [], progressValues: [InspectionProgress] = []
    private var prefixValue = Data(), publishedValue = false, returnedValue = false
    func read(descriptor: Int32, offset: off_t, requested: Int, bytes: UnsafeMutableRawBufferPointer, count: Int) {
        lock.withLock {
            readValues.append(Read(descriptor: descriptor, offset: offset, requested: requested, count: count,
                                   flags: Darwin.fcntl(descriptor, F_GETFL)))
            if offset == off_t(prefixValue.count), offset < 1_048_576, count > 0 {
                prefixValue.append(contentsOf: bytes.bindMemory(to: UInt8.self).prefix(min(count, 1_048_576 - prefixValue.count)))
            }
        }
    }
    func closed(_ descriptor: Int32, _ status: Int32) { lock.withLock { closeValues.append(Close(descriptor: descriptor, status: status)) } }
    func progress(_ value: InspectionProgress) { lock.withLock { progressValues.append(value) } }
    func published() { lock.withLock { publishedValue = true } }
    func returned() { lock.withLock { returnedValue = true } }
    var reads: [Read] { lock.withLock { readValues } }
    var closes: [Close] { lock.withLock { closeValues } }
    var updates: [InspectionProgress] { lock.withLock { progressValues } }
    var prefix: Data { lock.withLock { prefixValue } }
    var didPublish: Bool { lock.withLock { publishedValue } }
    var didReturn: Bool { lock.withLock { returnedValue } }
}

private enum InspectionReadGateError: Error { case timeout, finishedBeforeEntry }
private final class InspectionReadGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var entered = false, released = false, finished = false
    private var waiters: [CheckedContinuation<Void, Error>] = []
    func enterAndWait() throws {
        condition.lock()
        entered = true; waiters.forEach { $0.resume(returning: ()) }; waiters = []
        let deadline = Date().addingTimeInterval(10)
        while !released {
            if !condition.wait(until: deadline) { condition.unlock(); throw InspectionReadGateError.timeout }
        }
        condition.unlock()
    }
    func waitUntilEntered() async throws {
        try await withCheckedThrowingContinuation { continuation in
            condition.lock()
            if entered { condition.unlock(); continuation.resume(returning: ()) }
            else if finished { condition.unlock(); continuation.resume(throwing: InspectionReadGateError.finishedBeforeEntry) }
            else { waiters.append(continuation); condition.unlock() }
        }
    }
    func inspectionFinished() {
        condition.lock()
        finished = true
        if !entered {
            waiters.forEach { $0.resume(throwing: InspectionReadGateError.finishedBeforeEntry) }; waiters = []
        }
        condition.unlock()
    }
    func release() { condition.lock(); released = true; condition.broadcast(); condition.unlock() }
}
