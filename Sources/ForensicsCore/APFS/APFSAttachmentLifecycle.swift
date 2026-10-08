import Foundation

/// Killing/reaping the utility client does not prove Apple's separate daemon
/// completed its pending operation. Only a confirmed natural command exit can
/// authorize inventory-based backing-image cleanup after an attach starts.
final class APFSAttachmentLifecycle {
    enum State: Equatable { case notStarted, running, confirmedTerminal }
    private(set) var state: State = .notStarted
    func clientStarted() { state = .running }
    func commandReachedTerminal() { state = .confirmedTerminal }
    var requiresQuarantine: Bool { state == .running }
}

enum APFSReadLifecycleStage: Sendable, Equatable {
    case attachClientStarted(Int32)
    case attachCommandTerminal
    case baseMountClientStarted(Int32)
    case baseMountCommandTerminal
    case snapshotMountClientStarted(Int32)
    case snapshotMountCommandTerminal
    case mounted
    case detached
    /// Fixed stage labels and kernel flag bits only; no paths/content/keys.
    case safetyFailure(stage: String, mountFlags: UInt32?)
}
