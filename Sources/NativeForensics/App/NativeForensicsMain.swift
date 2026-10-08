import Darwin
import Foundation
import ForensicsCore
import SwiftUI

/// A local diagnostic must run as the actual bundled application so launchd
/// resolves its private embedded service and the service authenticates its host.
/// Normal desktop launch continues through the public SwiftUI App entry point.
@main
@MainActor
enum NativeForensicsMain {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.first == "--content-index-probe" {
            Task.detached {
                let code = await ContentIndexBundledProbe.run(Array(arguments.dropFirst()))
                Darwin.exit(code)
            }
            RunLoop.main.run()
            return
        }
        guard arguments.first == "--document-xpc-probe" else {
            NativeForensicsApp.main()
            return
        }
        Task.detached {
            let code = await DocumentXPCBundledProbe.run(Array(arguments.dropFirst()))
            Darwin.exit(code)
        }
        RunLoop.main.run()
    }
}

private enum DocumentXPCBundledProbe {
    static func run(_ arguments: [String]) async -> Int32 {
        do {
            guard Bundle.main.bundleURL.pathExtension == "app", arguments.count.isMultiple(of: 2) else { throw ProbeError.arguments }
            var values: [String: String] = [:]
            let keys = ["--input", "--sha256", "--bytes", "--timeout", "--mode", "--repeat", "--cancel-marker"]
            for index in stride(from: 0, to: arguments.count, by: 2) {
                guard keys.contains(arguments[index]), values[arguments[index]] == nil else { throw ProbeError.arguments }
                values[arguments[index]] = arguments[index + 1]
            }
            guard let path = values["--input"], let hash = values["--sha256"],
                  hash.utf8.count == 64, hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  let bytes = Int64(values["--bytes"] ?? ""), (0...DocumentLimits.maximumInputBytes).contains(bytes),
                  let timeout = Double(values["--timeout"] ?? "12"), timeout.isFinite, timeout > 0, timeout <= 120 else {
                throw ProbeError.arguments
            }
            let mode = values["--mode"] ?? "analyze"
            guard ["analyze", "cancel", "concurrent", "sustained", "cancel-early", "cancel-early-recover"].contains(mode) else { throw ProbeError.arguments }
            let earlyCancellation = ["cancel-early", "cancel-early-recover"].contains(mode)
            let repetitions = Int(values["--repeat"] ?? "16") ?? 0
            guard (2...64).contains(repetitions), values["--repeat"] == nil || mode == "sustained",
                  values["--cancel-marker"] == nil || earlyCancellation else { throw ProbeError.arguments }
            let marker = earlyCancellation ? try cancellationMarker(values["--cancel-marker"]) : nil
            defer { if let marker { Darwin.close(marker.parentDescriptor) } }
            let input = DocumentInput(fileURL: URL(fileURLWithPath: path), expectedSHA256: hash, expectedByteCount: bytes)
            let client = DocumentAnalysisClient(timeout: timeout)
            let events = ProbeEvents(maximumEvents: mode == "sustained" ? 4 * repetitions : 32)
            let start = DispatchTime.now().uptimeNanoseconds
            let results: [Attempt]
            switch mode {
            case "sustained":
                var attempts: [Attempt] = []
                for ordinal in 1...repetitions {
                    attempts.append(await attempt(client: client, input: input, ordinal: ordinal, events: events))
                }
                results = attempts
            case "cancel-early", "cancel-early-recover":
                let task = Task { await attempt(client: client, input: input, ordinal: 1, events: events) }
                let deadline = ProcessInfo.processInfo.systemUptime + min(timeout + 2, 15)
                var observed = false
                while ProcessInfo.processInfo.systemUptime < deadline {
                    if let marker, markerExists(marker) { observed = true; break }
                    try await Task.sleep(for: .milliseconds(1))
                }
                events.recordDiagnostic(observed ? "cancelRequested" : "cancelMarkerDeadline")
                task.cancel()
                let cancelled = await task.value
                // The public client completes owned cleanup before returning.
                // Keep this application host alive and attempt fresh work in
                // its existing XPC application-service namespace afterward.
                if mode == "cancel-early-recover" {
                    results = [cancelled, await attempt(client: client, input: input, ordinal: 2, events: events)]
                } else { results = [cancelled] }
            case "concurrent":
                async let first = attempt(client: client, input: input, ordinal: 1, events: events)
                async let second = attempt(client: client, input: input, ordinal: 2, events: events)
                results = await [first, second]
            case "cancel":
                let task = Task { await attempt(client: client, input: input, ordinal: 1, events: events) }
                // Cancel after observed service ownership, allowing its parsing
                // queue to start. This is distinct from cancel during source hash.
                for _ in 0..<1_500 {
                    if events.started { break }
                    if task.isCancelled { break }
                    try await Task.sleep(for: .milliseconds(10))
                }
                try await Task.sleep(for: .milliseconds(50))
                task.cancel()
                results = [await task.value]
            default:
                results = [await attempt(client: client, input: input, ordinal: 1, events: events)]
            }
            let report = Report(schemaVersion: 1, backend: "embedded-app-sandbox-xpc", mode: mode,
                available: client.isAvailable, durationNanoseconds: DispatchTime.now().uptimeNanoseconds - start,
                sourceSHA256: hash, sourceByteCount: bytes, attempts: results, events: events.snapshot)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            let encoded = try encoder.encode(report)
            guard encoded.count <= DocumentLimits.maximumResponseBytes * results.count + 65_536 else { throw ProbeError.outputLimit }
            FileHandle.standardOutput.write(encoded)
            FileHandle.standardOutput.write(Data([10]))
            return 0
        } catch {
            FileHandle.standardError.write(Data("Bundled document probe failed: \(String(describing: type(of: error)))\n".utf8))
            return 64
        }
    }

    private static func attempt(client: DocumentAnalysisClient, input: DocumentInput, ordinal: Int,
                                events: ProbeEvents) async -> Attempt {
        do {
            let analysis = try await client.analyze(input) { events.record($0, ordinal: ordinal) }
            return Attempt(ordinal: ordinal, analysis: analysis, errorCode: nil)
        } catch is CancellationError {
            return Attempt(ordinal: ordinal, analysis: nil, errorCode: "cancelled")
        } catch let error as DocumentAnalysisError {
            return Attempt(ordinal: ordinal, analysis: nil, errorCode: String(describing: error))
        } catch {
            return Attempt(ordinal: ordinal, analysis: nil, errorCode: "unexpected-error")
        }
    }

    private struct Attempt: Encodable { let ordinal: Int; let analysis: DocumentAnalysis?; let errorCode: String? }
    private struct Event: Encodable {
        let ordinal: Int; let kind: String; let processIdentifier: Int32; let uptimeNanoseconds: UInt64
    }
    private struct Report: Encodable {
        let schemaVersion: Int; let backend: String; let mode: String; let available: Bool
        let durationNanoseconds: UInt64; let sourceSHA256: String; let sourceByteCount: Int64
        let attempts: [Attempt]; let events: [Event]
    }
    private final class ProbeEvents: @unchecked Sendable {
        private let lock = NSLock()
        private let maximumEvents: Int
        private var events: [Event] = []
        init(maximumEvents: Int) { self.maximumEvents = maximumEvents }
        var snapshot: [Event] { lock.withLock { events } }
        var started: Bool { lock.withLock { events.contains { $0.kind == "started" } } }
        func record(_ event: DocumentDecoderLifecycleEvent, ordinal: Int) {
            let value: Event
            switch event {
            case .started(let pid, _):
                value = Event(ordinal: ordinal, kind: "started", processIdentifier: pid,
                    uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds)
            case .exited(let pid):
                value = Event(ordinal: ordinal, kind: "exited", processIdentifier: pid,
                    uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds)
            }
            lock.withLock { if events.count < maximumEvents { events.append(value) } }
        }
        func recordDiagnostic(_ kind: String) {
            lock.withLock {
                if events.count < maximumEvents {
                    events.append(Event(ordinal: 1, kind: kind, processIdentifier: 0,
                        uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds))
                }
            }
        }
    }

    /// The marker is a synthetic coordinator control, never document input.
    /// Its private, pinned parent prevents observing someone else's leaf.
    private struct CancellationMarker {
        let url: URL
        let parentDescriptor: Int32
        let parentDevice: dev_t
        let parentInode: ino_t
    }
    private static func cancellationMarker(_ path: String?) throws -> CancellationMarker {
        guard let path, path.hasPrefix("/"), !path.utf8.contains(0) else { throw ProbeError.arguments }
        let url = URL(fileURLWithPath: path).standardizedFileURL
        let parent = url.deletingLastPathComponent()
        var metadata = stat(), existing = stat()
        guard url.lastPathComponent.hasPrefix(".nativeforensics-xpc-cancel-"), url.pathExtension == "marker",
              parent == parent.resolvingSymlinksInPath(), Darwin.lstat(parent.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_uid == Darwin.getuid(),
              metadata.st_mode & 0o077 == 0,
              Darwin.lstat(url.path, &existing) == -1, errno == ENOENT else { throw ProbeError.arguments }
        let descriptor = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var pinned = stat()
        guard descriptor >= 0 else { throw ProbeError.arguments }
        guard Darwin.fstat(descriptor, &pinned) == 0, pinned.st_dev == metadata.st_dev,
              pinned.st_ino == metadata.st_ino else { Darwin.close(descriptor); throw ProbeError.arguments }
        return CancellationMarker(url: url, parentDescriptor: descriptor, parentDevice: pinned.st_dev, parentInode: pinned.st_ino)
    }
    private static func markerExists(_ marker: CancellationMarker) -> Bool {
        var parent = stat(), pathParent = stat(), leaf = stat()
        guard Darwin.fstat(marker.parentDescriptor, &parent) == 0,
              Darwin.lstat(marker.url.deletingLastPathComponent().path, &pathParent) == 0,
              pathParent.st_dev == parent.st_dev, pathParent.st_ino == parent.st_ino,
              parent.st_mode & S_IFMT == S_IFDIR, parent.st_uid == Darwin.getuid(), parent.st_mode & 0o077 == 0,
              parent.st_dev == marker.parentDevice, parent.st_ino == marker.parentInode,
              Darwin.fstatat(marker.parentDescriptor, marker.url.lastPathComponent, &leaf, AT_SYMLINK_NOFOLLOW) == 0 else { return false }
        return leaf.st_mode & S_IFMT == S_IFREG && leaf.st_uid == Darwin.getuid() && leaf.st_nlink == 1
            && leaf.st_size == 1
    }
    private enum ProbeError: Error { case arguments, outputLimit }
}
