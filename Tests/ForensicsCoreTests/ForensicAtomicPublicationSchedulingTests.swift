import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("ForensicAtomicPublicationSchedulingTests")
struct ForensicAtomicPublicationSchedulingTests {
    @Test("Cancellation before atomic worker creation publishes nothing")
    func cancellationBeforeCreation() async throws {
        let scheduler = ForensicWorkScheduler(), start = AtomicAsyncBarrier(), log = AtomicPublicationLog()
        let permit = try await scheduler.acquireImmediately(.filesystemAnalysis)
        let owner = Task {
            await start.wait()
            return try await permit.runToCompletion { await log.append("must-not-start"); return 1 }
        }
        owner.cancel(); await start.open()
        await #expect(throws: CancellationError.self) { try await owner.value }
        #expect(await log.values.isEmpty)
        #expect(await scheduler.state().active?.id == permit.admission.id)
        #expect(await permit.release())
        #expect(await scheduler.state().active == nil)
    }

    @Test("An atomic writer already holding its FD publishes despite late cancel and retains admission through drain")
    func cancellationAfterAtomicStart() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("nf-atomic-scheduling-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let bytes = Data("synthetic atomic publication with complete byte oracle".utf8)
        let destination = directory.appendingPathComponent("committed.json")
        let stage = directory.appendingPathComponent("owned-stage")
        let scheduler = ForensicWorkScheduler(), writerGate = AtomicWriterGate()
        let drain = AtomicAsyncBarrier(), log = AtomicPublicationLog()
        await scheduler.updatePolicy(mode: .conserveEnergy,
            context: .init(powerSource: .externalPower, thermalState: .nominal))
        let permit = try await scheduler.acquireImmediately(.filesystemAnalysis)
        let owner = Task {
            do {
                let queuePriority = try await permit.runToCompletion {
                    #expect(ForensicWorkExecutionContext.requestedPriority == .utility)
                    let requested = try await BlockingWork.run {
                        let fd = Darwin.open(stage.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
                        guard fd >= 0 else { throw AtomicSchedulingTestError.fileOperation }
                        defer { Darwin.close(fd) }
                        try bytes.withUnsafeBytes { buffer in
                            guard let address = buffer.baseAddress,
                                  Darwin.write(fd, address, 1) == 1 else { throw AtomicSchedulingTestError.fileOperation }
                            // The independent oracle observes an owned live FD
                            // with staged bytes before cancellation is issued.
                            try writerGate.enterAndWait()
                            var offset = 1
                            while offset < buffer.count {
                                let written = Darwin.write(fd, address.advanced(by: offset), buffer.count - offset)
                                if written < 0 && errno == EINTR { continue }
                                guard written > 0 else { throw AtomicSchedulingTestError.fileOperation }
                                offset += written
                            }
                        }
                        guard Darwin.fsync(fd) == 0,
                              Darwin.link(stage.path, destination.path) == 0,
                              Darwin.unlink(stage.path) == 0 else { throw AtomicSchedulingTestError.fileOperation }
                        return BlockingWork.queuePriorityForTesting
                    }
                    // This would throw if late parent cancellation had been
                    // forwarded to the owned publisher's detached Task.
                    try Task.checkCancellation()
                    return requested
                }
                await log.append("published")
                await drain.wait()
                _ = await permit.release()
                return queuePriority
            } catch {
                _ = await permit.release()
                throw error
            }
        }
        var waiting: Task<Void, Error>?
        do {
            try await atomicWait { writerGate.hasEntered }
            #expect(FileManager.default.fileExists(atPath: stage.path))
            #expect(!FileManager.default.fileExists(atPath: destination.path))
            let next = Task {
                let admitted = try await scheduler.acquire(.contentIndex)
                await log.append("next-start")
                _ = await admitted.release()
            }
            waiting = next
            try await atomicWait { await scheduler.state().queuedKinds == [.contentIndex] }
            owner.cancel()
            #expect(await scheduler.state().active?.id == permit.admission.id)
            writerGate.open()
            try await atomicWait { await log.values == ["published"] }
            #expect(try Data(contentsOf: destination) == bytes)
            #expect(!FileManager.default.fileExists(atPath: stage.path))
            #expect(await scheduler.state().active?.id == permit.admission.id)
            #expect(await scheduler.state().queuedKinds == [.contentIndex])
            await drain.open()
            #expect(try await owner.value == .utility)
            try await next.value
            #expect(await log.values == ["published", "next-start"])
            #expect(await scheduler.state().active == nil)
        } catch {
            writerGate.open(); await drain.open()
            owner.cancel(); waiting?.cancel()
            _ = try? await owner.value
            if let waiting { _ = try? await waiting.value }
            _ = await permit.release()
            throw error
        }
    }
}

private enum AtomicSchedulingTestError: Error { case fileOperation, waitExpired }

private final class AtomicWriterGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var entered = false
    private var isOpen = false
    var hasEntered: Bool { condition.lock(); defer { condition.unlock() }; return entered }
    func enterAndWait() throws {
        condition.lock(); defer { condition.unlock() }
        entered = true
        let deadline = Date().addingTimeInterval(5)
        while !isOpen {
            guard condition.wait(until: deadline) || isOpen else { throw AtomicSchedulingTestError.waitExpired }
        }
    }
    func open() { condition.lock(); isOpen = true; condition.broadcast(); condition.unlock() }
}

private actor AtomicAsyncBarrier {
    private var isOpen = false
    private var waiting: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { waiting.append($0) }
    }
    func open() {
        isOpen = true
        let owners = waiting; waiting.removeAll()
        for owner in owners { owner.resume() }
    }
}

private actor AtomicPublicationLog {
    private(set) var values: [String] = []
    func append(_ value: String) { values.append(value) }
}

private func atomicWait(_ condition: () async -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while !(await condition()) {
        guard ContinuousClock.now < deadline else { throw AtomicSchedulingTestError.waitExpired }
        try await Task.sleep(for: .milliseconds(1))
    }
}
