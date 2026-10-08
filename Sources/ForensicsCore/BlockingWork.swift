import Dispatch

/// POSIX process polling must not occupy Swift's cooperative executor. Callers
/// retain their own cancellation token and await this continuation until the
/// operation has finished unwinding and reaping its owned child.
enum BlockingWork {
    private final class QueueMarker: @unchecked Sendable {
        let key = DispatchSpecificKey<ForensicWorkPriority>()
    }
    private static let marker = QueueMarker()
    private static let foregroundQueue: DispatchQueue = {
        let queue = DispatchQueue(label: "io.nativeforensics.blocking-work", qos: .userInitiated, attributes: .concurrent)
        queue.setSpecific(key: marker.key, value: .userInitiated)
        return queue
    }()
    private static let utilityQueue: DispatchQueue = {
        let queue = DispatchQueue(label: "io.nativeforensics.blocking-work.utility", qos: .utility, attributes: .concurrent)
        queue.setSpecific(key: marker.key, value: .utility)
        return queue
    }()
    /// A test reads the marker inside the dispatched operation, proving the
    /// selected queue rather than assuming awaited Task priority cannot rise.
    static var queuePriorityForTesting: ForensicWorkPriority? { DispatchQueue.getSpecific(key: marker.key) }

    static func run<Value: Sendable>(
        _ operation: @escaping @Sendable () throws -> Value
    ) async throws -> Value {
        let queue = ForensicWorkExecutionContext.requestedPriority == .utility ? utilityQueue : foregroundQueue
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do { continuation.resume(returning: try operation()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }
}
