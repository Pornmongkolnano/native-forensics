import Foundation
import ForensicsCore
import QuartzCore
import Darwin

/// Local diagnostic only. Normal app launches retain no timing receipts.
/// Worker callbacks may use this object without hopping to the UI actor.
final class UIInteractionTiming: @unchecked Sendable {
    static let shared = UIInteractionTiming(
        enabled: ProcessInfo.processInfo.environment["NF_UI_TIMING"] == "1")

    let isEnabled: Bool
    private let trace: UIInteractionTrace?
    private let uptime: @Sendable () -> TimeInterval

    init(enabled: Bool, uptime: @escaping @Sendable () -> TimeInterval = { CACurrentMediaTime() }) {
        isEnabled = enabled
        trace = enabled ? UIInteractionTrace() : nil
        self.uptime = uptime
    }

    /// Measures binding receipt by default. A controlled input event timestamp
    /// may be supplied explicitly after its clock domain and freshness are checked.
    /// Never infer that timestamp from NSApplication.currentEvent.
    @discardableResult
    func begin(inputEventUptimeSeconds: TimeInterval? = nil) -> UInt64? {
        guard let trace else { return nil }
        return trace.begin(at: uptime(), inputEventUptimeSeconds: inputEventUptimeSeconds)
    }

    /// Attachment follows the owned editor's dispatch, so ambiguous edits retain
    /// their original binding-only stage clocks and ordinary search behavior.
    @discardableResult
    func associateFilesystemInputEvent(_ receipt: UIInteractionInputReceipt, trialID: UInt64) -> Bool {
        trace?.associateInputEvent(receipt, trialID: trialID) ?? false
    }

    func reserveInputEventSequence() -> UInt64? { trace?.reserveInputEventSequence() }

    func recordInputRejection(_ rejection: UIInteractionInputRejection) {
        trace?.recordInputRejection(rejection)
    }

    @discardableResult
    func record(_ stage: UIInteractionStage, trialID: UInt64?) -> Bool {
        guard let trace, let trialID else { return false }
        return trace.record(stage, trialID: trialID, at: uptime())
    }

    @discardableResult
    func finish(_ outcome: UIInteractionOutcome, trialID: UInt64?) -> Bool {
        guard let trace, let trialID else { return false }
        return trace.finish(outcome, trialID: trialID, at: uptime())
    }

    func snapshot() -> UIInteractionTraceReport { trace?.snapshot() ?? UIInteractionTraceReport() }

    /// Opt-in diagnostic publication after app-owned work has drained. Normal
    /// launches have no destination and perform no filesystem write. Returning
    /// false conveys a generic policy/write failure, without exposing a path.
    @discardableResult
    func writeRequestedReport() -> Bool? {
        guard isEnabled else { return nil }
        guard let destination = ProcessInfo.processInfo.environment["NF_UI_TIMING_OUTPUT"] else { return nil }
        return writeReport(to: destination)
    }

    /// Internal injected destination lets safety tests avoid changing the app's
    /// environment or touching existing cases. Output contains numeric trials.
    func writeReport(to path: String) -> Bool {
        guard isEnabled, path.hasPrefix("/"), !path.utf8.contains(0) else { return false }
        let output = URL(fileURLWithPath: path).standardizedFileURL
        let parent = output.deletingLastPathComponent(), name = output.lastPathComponent
        let prefix = ".nativeforensics-ui-timing-", suffix = ".json"
        guard output.path == path, parent.path == parent.resolvingSymlinksInPath().path,
              name.hasPrefix(prefix), name.hasSuffix(suffix), name.utf8.count <= 128,
              name.count > prefix.count + suffix.count else { return false }
        let middle = name.dropFirst(prefix.count).dropLast(suffix.count)
        guard middle.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0)
            || (97...122).contains($0) || $0 == 45 || $0 == 95 }) else { return false }

        guard let directory = Self.openPinnedDirectory(parent.path) else { return false }
        defer { Darwin.close(directory) }
        var parentStat = stat()
        guard Darwin.fstat(directory, &parentStat) == 0,
              parentStat.st_uid == Darwin.geteuid(), (parentStat.st_mode & 0o7777) == 0o700 else { return false }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard let bytes = try? encoder.encode(snapshot()), bytes.count <= 1_048_576 else { return false }
        let descriptor = Darwin.openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { return false }
        defer { Darwin.close(descriptor) }
        var original = stat()
        guard Darwin.fstat(descriptor, &original) == 0 else { return false }
        // fchmod makes the diagnostic permission explicit even under a stricter
        // ambient umask. It never targets an existing file.
        guard Darwin.fchmod(descriptor, 0o600) == 0 else { Self.removeOwnedPartial(directory, name, original); return false }
        let written = bytes.withUnsafeBytes { buffer -> Bool in
            guard let start = buffer.baseAddress else { return bytes.isEmpty }
            var offset = 0
            while offset < buffer.count {
                let amount = Darwin.write(descriptor, start.advanced(by: offset), buffer.count - offset)
                if amount < 0 && errno == EINTR { continue }
                guard amount > 0 else { return false }
                offset += amount
            }
            return true
        }
        guard written, Darwin.fsync(descriptor) == 0 else { Self.removeOwnedPartial(directory, name, original); return false }
        var actual = stat()
        guard Darwin.fstat(descriptor, &actual) == 0, actual.st_dev == original.st_dev,
              actual.st_ino == original.st_ino, actual.st_uid == Darwin.geteuid(),
              (actual.st_mode & 0o7777) == 0o600, actual.st_size == Int64(bytes.count) else {
            Self.removeOwnedPartial(directory, name, original); return false
        }
        // Directory-flush failure leaves the new diagnostic for inspection and
        // returns uncertainty; it does not remove a fully written report.
        return Darwin.fsync(directory) == 0
    }

    private static func openPinnedDirectory(_ path: String) -> Int32? {
        var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        for component in path.split(separator: "/") {
            let next = Darwin.openat(descriptor, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            Darwin.close(descriptor)
            guard next >= 0 else { return nil }
            descriptor = next
        }
        return descriptor
    }

    private static func removeOwnedPartial(_ directory: Int32, _ name: String, _ original: stat) {
        var named = stat()
        guard Darwin.fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == original.st_dev, named.st_ino == original.st_ino,
              named.st_uid == Darwin.geteuid() else { return }
        _ = Darwin.unlinkat(directory, name, 0)
        _ = Darwin.fsync(directory)
    }
}
