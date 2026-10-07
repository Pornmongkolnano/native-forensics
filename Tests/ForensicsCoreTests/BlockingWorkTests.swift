import Dispatch
import Foundation
import Testing
@testable import ForensicsCore

struct BlockingWorkTests {
    @Test("An async caller resumes while its blocking worker waits for that caller")
    func callerCanReleaseBlockedWorker() async throws {
        let gate = DispatchSemaphore(value: 0)
        let watchdogState = BlockingWatchdogState()
        let (started, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let work = Task {
            defer { continuation.finish() }
            return try await BlockingWork.run {
                continuation.yield(())
                // This is deliberately a blocking operation. The caller must
                // resume and release it even with a one-thread Swift executor.
                // A separate queue supplies only a failure/cleanup watchdog.
                gate.wait()
                return 42
            }
        }
        let watchdog = DispatchWorkItem { watchdogState.fire(); gate.signal() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 30, execute: watchdog)
        defer { watchdog.cancel(); gate.signal() }
        var iterator = started.makeAsyncIterator()
        _ = await iterator.next()
        #expect(!watchdogState.didFire)
        gate.signal()
        #expect(try await work.value == 42)
    }
}

private final class BlockingWatchdogState: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    func fire() { lock.withLock { fired = true } }
    var didFire: Bool { lock.withLock { fired } }
}
