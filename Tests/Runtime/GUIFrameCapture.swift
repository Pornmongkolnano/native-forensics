// Standalone macOS 14+ diagnostic; outside every SwiftPM target.
// Compile this absolute source path with swiftc -parse-as-library when authorized.
// It never requests screen permission and captures only an explicitly attested synthetic window.
import AppKit
import CoreGraphics
import CoreMedia
import CoreVideo
import CryptoKit
import Darwin
import Foundation
import ImageIO
import QuartzCore
import ScreenCaptureKit
import UniformTypeIdentifiers

private enum CaptureFailure: Error {
    case reason(String)
}

private struct CaptureOptions {
    let pid: pid_t
    let appBundle: URL
    let listOwned: Bool
    let windowID: CGWindowID?
    let displayID: CGDirectDisplayID?
    let output: URL?
    let seconds: Double
    let maximumFrames: Int
    let maximumPixels: Int
    let maximumBytes: Int

    init(_ arguments: [String]) throws {
        let valueKeys: Set<String> = ["--pid", "--app-bundle", "--window-id", "--display-id", "--output",
            "--seconds", "--max-frames", "--max-pixels", "--max-bytes"]
        let flagKeys: Set<String> = ["--synthetic-only", "--list-owned"]
        var values: [String: String] = [:]
        var flags: Set<String> = []
        var index = 0
        while index < arguments.count {
            let key = arguments[index]
            if flagKeys.contains(key) {
                guard flags.insert(key).inserted else { throw CaptureFailure.reason("duplicate-argument") }
                index += 1
            } else {
                guard valueKeys.contains(key), values[key] == nil, index + 1 < arguments.count else {
                    throw CaptureFailure.reason("invalid-arguments")
                }
                values[key] = arguments[index + 1]
                index += 2
            }
        }
        guard flags.contains("--synthetic-only"), let pidText = values["--pid"],
              let pidValue = Int32(pidText), pidValue > 0,
              let bundlePath = values["--app-bundle"], Self.isAbsoluteCleanPath(bundlePath),
              bundlePath.hasSuffix(".app") else { throw CaptureFailure.reason("synthetic-identity-required") }
        pid = pidValue
        appBundle = URL(fileURLWithPath: bundlePath, isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
        listOwned = flags.contains("--list-owned")
        seconds = Double(values["--seconds"] ?? "10") ?? .nan
        maximumFrames = Int(values["--max-frames"] ?? "512") ?? 0
        maximumPixels = Int(values["--max-pixels"] ?? "4000000") ?? 0
        maximumBytes = Int(values["--max-bytes"] ?? "134217728") ?? 0
        guard seconds.isFinite, seconds > 0, seconds <= 60,
              (1...512).contains(maximumFrames), (1...4_000_000).contains(maximumPixels),
              (2_097_152...134_217_728).contains(maximumBytes) else {
            throw CaptureFailure.reason("invalid-limits")
        }
        if listOwned {
            guard values["--window-id"] == nil, values["--display-id"] == nil, values["--output"] == nil else {
                throw CaptureFailure.reason("list-mode-does-not-capture")
            }
            windowID = nil; displayID = nil; output = nil
        } else {
            guard let windowText = values["--window-id"], let window = UInt32(windowText), window != 0,
                  let displayText = values["--display-id"], let display = UInt32(displayText), display != 0,
                  let outputPath = values["--output"], Self.isAbsoluteCleanPath(outputPath) else {
                throw CaptureFailure.reason("exact-window-display-output-required")
            }
            windowID = window; displayID = display
            output = URL(fileURLWithPath: outputPath, isDirectory: true).standardizedFileURL
        }
    }

    static func isAbsoluteCleanPath(_ path: String) -> Bool {
        path.hasPrefix("/") && !path.utf8.contains(0) && !path.split(separator: "/", omittingEmptySubsequences: false)
            .contains(where: { $0 == "." || $0 == ".." })
    }
}

/// Immutable owned-process birth, rather than PID/object equality alone.
private struct ProcessBirth: Equatable, Sendable {
    let seconds: UInt64
    let microseconds: UInt64

    static func read(_ pid: pid_t) -> Self? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
              info.pbi_pid == UInt32(pid), info.pbi_uid == geteuid(),
              info.pbi_start_tvsec > 0, info.pbi_start_tvusec < 1_000_000 else { return nil }
        return Self(seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec)
    }
}

private struct ApplicationIdentity: Equatable, Sendable {
    let launchDate: Date
    let birth: ProcessBirth
}

private struct NumericRect: Encodable {
    let x: Double; let y: Double; let width: Double; let height: Double
    init(_ rect: CGRect) {
        x = Double(rect.origin.x); y = Double(rect.origin.y)
        width = Double(rect.width); height = Double(rect.height)
    }
}

/// Opens every output ancestor without following symlinks, then makes one fresh directory.
private final class ExclusiveOutput: @unchecked Sendable {
    static let summaryReserve = 1_048_576
    private let parentFD: Int32
    private let directoryFD: Int32
    private let parentIdentity: stat
    private let directoryIdentity: stat
    private let leafName: String
    private let maximumBytes: Int
    private(set) var bytesWritten = 0

    init(url: URL, maximumBytes: Int) throws {
        let source = URL(fileURLWithPath: #filePath).standardizedFileURL
        let repository = source.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let ignoredRoot = repository.appendingPathComponent("local", isDirectory: true)
        let ignoreURL = repository.appendingPathComponent(".gitignore")
        guard let ignored = try? String(contentsOf: ignoreURL, encoding: .utf8), ignored.utf8.count <= 262_144,
              ignored.split(whereSeparator: \.isNewline).contains("local/"),
              url.path.hasPrefix(ignoredRoot.path + "/") else {
            throw CaptureFailure.reason("output-must-be-under-ignored-local")
        }
        let components = url.pathComponents.filter { $0 != "/" }
        guard let leaf = components.last, !leaf.isEmpty else { throw CaptureFailure.reason("invalid-output") }
        var parent = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw CaptureFailure.reason("output-open-failed") }
        for component in components.dropLast() {
            let next = component.withCString { Darwin.openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
            guard next >= 0 else { Darwin.close(parent); throw CaptureFailure.reason("output-ancestor-not-safe-directory") }
            Darwin.close(parent); parent = next
        }
        var transferred = false
        defer { if !transferred { Darwin.close(parent) } }
        var parentState = stat()
        guard Darwin.fstat(parent, &parentState) == 0, (parentState.st_mode & S_IFMT) == S_IFDIR,
              parentState.st_uid == geteuid(), (parentState.st_mode & 0o7777) == 0o700 else {
            throw CaptureFailure.reason("output-parent-must-be-private-owned-directory")
        }
        guard leaf.withCString({ Darwin.mkdirat(parent, $0, 0o700) }) == 0 else {
            throw CaptureFailure.reason("output-directory-must-be-fresh")
        }
        let fd = leaf.withCString { Darwin.openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
        guard fd >= 0 else { throw CaptureFailure.reason("output-directory-open-failed") }
        var opened = stat(); var named = stat()
        guard Darwin.fstat(fd, &opened) == 0, (opened.st_mode & S_IFMT) == S_IFDIR,
              leaf.withCString({ Darwin.fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW) }) == 0,
              opened.st_dev == named.st_dev, opened.st_ino == named.st_ino,
              opened.st_uid == geteuid(), named.st_uid == geteuid(), (named.st_mode & S_IFMT) == S_IFDIR,
              Darwin.fchmod(fd, 0o700) == 0, Darwin.fstat(fd, &opened) == 0,
              leaf.withCString({ Darwin.fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW) }) == 0,
              opened.st_dev == named.st_dev, opened.st_ino == named.st_ino,
              opened.st_uid == geteuid(), named.st_uid == geteuid(),
              (opened.st_mode & 0o7777) == 0o700, (named.st_mode & 0o7777) == 0o700,
              Darwin.fsync(parent) == 0 else {
            Darwin.close(fd); throw CaptureFailure.reason("output-directory-identity-changed")
        }
        parentFD = parent; parentIdentity = parentState
        directoryIdentity = opened; leafName = leaf
        directoryFD = fd
        self.maximumBytes = maximumBytes
        transferred = true
    }

    deinit { Darwin.close(directoryFD); Darwin.close(parentFD) }

    func writePNG(_ data: Data, name: String) throws {
        guard data.count <= maximumBytes - Self.summaryReserve - bytesWritten else {
            throw CaptureFailure.reason("output-byte-limit")
        }
        try writeExclusive(data, name: name)
    }

    func writeSummary(_ data: Data) throws {
        guard data.count <= Self.summaryReserve, data.count <= maximumBytes - bytesWritten else {
            throw CaptureFailure.reason("summary-byte-limit")
        }
        try writeExclusive(data, name: "summary.json")
    }

    private func writeExclusive(_ data: Data, name: String) throws {
        guard !name.contains("/"), name != ".", name != ".." else { throw CaptureFailure.reason("invalid-output-name") }
        try verifyDirectory()
        let fd = name.withCString { Darwin.openat(directoryFD, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600) }
        guard fd >= 0 else { throw CaptureFailure.reason("exclusive-output-open-failed") }
        defer { Darwin.close(fd) }
        var identity = stat()
        guard Darwin.fstat(fd, &identity) == 0, (identity.st_mode & S_IFMT) == S_IFREG,
              identity.st_uid == geteuid(), identity.st_nlink == 1,
              Darwin.fchmod(fd, 0o600) == 0 else { throw CaptureFailure.reason("output-file-not-private-owned-regular") }
        try verifyFile(fd, name: name, identity: identity, byteCount: 0)
        try data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(fd, base.advanced(by: offset), bytes.count - offset)
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { throw CaptureFailure.reason("output-write-failed") }
                offset += written; bytesWritten += written
            }
        }
        guard Darwin.fsync(fd) == 0 else { throw CaptureFailure.reason("output-sync-failed") }
        try verifyFile(fd, name: name, identity: identity, byteCount: data.count)
        try verifyDirectory()
        guard Darwin.fsync(directoryFD) == 0 else { throw CaptureFailure.reason("output-directory-sync-failed") }
    }

    private func verifyDirectory() throws {
        var parent = stat(); var opened = stat(); var named = stat()
        guard Darwin.fstat(parentFD, &parent) == 0, parent.st_dev == parentIdentity.st_dev,
              parent.st_ino == parentIdentity.st_ino, (parent.st_mode & S_IFMT) == S_IFDIR,
              parent.st_uid == geteuid(), (parent.st_mode & 0o7777) == 0o700,
              Darwin.fstat(directoryFD, &opened) == 0,
              leafName.withCString({ Darwin.fstatat(parentFD, $0, &named, AT_SYMLINK_NOFOLLOW) }) == 0,
              opened.st_dev == directoryIdentity.st_dev, opened.st_ino == directoryIdentity.st_ino,
              named.st_dev == opened.st_dev, named.st_ino == opened.st_ino,
              (opened.st_mode & S_IFMT) == S_IFDIR, (named.st_mode & S_IFMT) == S_IFDIR,
              opened.st_uid == geteuid(), named.st_uid == geteuid(),
              (opened.st_mode & 0o7777) == 0o700, (named.st_mode & 0o7777) == 0o700 else {
            throw CaptureFailure.reason("output-directory-binding-changed")
        }
    }

    private func verifyFile(_ fd: Int32, name: String, identity: stat, byteCount: Int) throws {
        var opened = stat(); var named = stat()
        guard Darwin.fstat(fd, &opened) == 0,
              name.withCString({ Darwin.fstatat(directoryFD, $0, &named, AT_SYMLINK_NOFOLLOW) }) == 0,
              opened.st_dev == identity.st_dev, opened.st_ino == identity.st_ino,
              named.st_dev == opened.st_dev, named.st_ino == opened.st_ino,
              (opened.st_mode & S_IFMT) == S_IFREG, (named.st_mode & S_IFMT) == S_IFREG,
              opened.st_uid == geteuid(), named.st_uid == geteuid(),
              (opened.st_mode & 0o7777) == 0o600, (named.st_mode & 0o7777) == 0o600,
              opened.st_nlink == 1, named.st_nlink == 1,
              opened.st_size == Int64(byteCount), named.st_size == Int64(byteCount) else {
            throw CaptureFailure.reason("output-file-binding-changed")
        }
    }
}

private struct FrameObservation: Encodable {
    let number: Int
    let png: String
    let displayTimeMachTicks: UInt64
    let displayUptimeSeconds: Double
    let callbackReceiptUptimeSeconds: Double
    let gapFromPreviousCompleteSeconds: Double?
    let width: Int; let height: Int
    let rawPixelSHA256: String; let pngSHA256: String
    let pngByteCount: Int
    let scaleFactor: Double?
    let contentScale: Double?
}

private struct CaptureReport: Encodable {
    let schemaVersion = 1
    let measurement = "captured-windowserver-presentation"
    let syntheticOnly = true
    let pid: Int32; let windowID: UInt32; let displayID: UInt32
    let pidBirthSeconds: UInt64; let pidBirthMicroseconds: UInt64
    let launchDateUnixSeconds: Double
    let sourceRectPoints: NumericRect
    let pointPixelScale: Double
    let configuredWidth: Int; let configuredHeight: Int
    let minimumFrameIntervalSeconds = 0
    let queueDepth = 3
    let capturesAudio = false; let showsCursor = false
    let maximumFrames: Int; let maximumPixels: Int; let maximumOutputBytes: Int
    let maximumDurationSeconds: Double
    let machTimebaseNumerator: UInt32; let machTimebaseDenominator: UInt32
    let startReceiptUptimeSeconds: Double
    let stopReceiptUptimeSeconds: Double
    let outcome: String; let reason: String?
    let outputPNGBytes: Int
    let statusCounts: [String: Int]
    let maximumObservedCompleteGapSeconds: Double
    let frames: [FrameObservation]
}

private final class CaptureRecorder: NSObject, SCStreamOutput, SCStreamDelegate, @unchecked Sendable {
    let queue = DispatchQueue(label: "NativeForensics.SyntheticFrameOracle", qos: .userInitiated)
    private let lock = NSLock()
    private let output: ExclusiveOutput
    private let options: CaptureOptions
    private let configuredWidth: Int
    private let configuredHeight: Int
    private let timebase: mach_timebase_info_data_t
    private let birth: ProcessBirth
    private let stop: AsyncStream<Void>.Continuation
    private var observations: [FrameObservation] = []
    private var statuses: [String: Int] = ["complete": 0, "idle": 0, "blank": 0,
        "suspended": 0, "started": 0, "stopped": 0, "unknown": 0, "invalid": 0]
    private var failureReason: String?
    private var accepting = true
    private var maximumGap = 0.0

    init(output: ExclusiveOutput, options: CaptureOptions, width: Int, height: Int,
         timebase: mach_timebase_info_data_t, birth: ProcessBirth, stop: AsyncStream<Void>.Continuation) {
        self.output = output; self.options = options; configuredWidth = width; configuredHeight = height
        self.timebase = timebase; self.birth = birth; self.stop = stop
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) { fail("stream-stopped-with-error") }

    func stream(_ stream: SCStream, didOutputSampleBuffer sampleBuffer: CMSampleBuffer,
                of outputType: SCStreamOutputType) {
        let receipt = CACurrentMediaTime()
        guard outputType == .screen else { return }
        autoreleasepool { processScreen(sampleBuffer, receipt: receipt) }
    }

    private func processScreen(_ sampleBuffer: CMSampleBuffer, receipt: Double) {
        guard lock.withLock({ accepting && failureReason == nil }) else { return }
        guard ProcessBirth.read(options.pid) == birth else { fail("app-birth-changed-during-capture"); return }
        guard sampleBuffer.isValid,
              let array = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false)
                as? [[SCStreamFrameInfo: Any]], let metadata = array.first,
              let rawStatus = metadata[.status] as? Int,
              let status = SCFrameStatus(rawValue: rawStatus) else { count("invalid"); return }
        switch status {
        case .complete: count("complete")
        case .idle: count("idle"); return
        case .blank: count("blank"); return
        case .suspended: count("suspended"); return
        case .started: count("started"); return
        case .stopped: count("stopped"); return
        @unknown default: count("unknown"); return
        }
        guard let timestamp = metadata[.displayTime] as? NSNumber,
              let buffer = sampleBuffer.imageBuffer else { fail("missing-complete-frame-data"); return }
        let rawTicks = timestamp.uint64Value
        let displaySeconds = Double(rawTicks) * Double(timebase.numer) / Double(timebase.denom) / 1_000_000_000
        let previous = lock.withLock { observations.last }
        guard rawTicks > 0, displaySeconds.isFinite, displaySeconds >= 0,
              receipt.isFinite, displaySeconds <= receipt + 0.050,
              previous.map({ rawTicks > $0.displayTimeMachTicks }) ?? true else {
            fail("invalid-display-clock"); return
        }
        guard lock.withLock({ observations.count < options.maximumFrames }) else { fail("frame-limit"); return }
        do {
            let (pixels, width, height) = try copyPixels(buffer)
            let png = try makePNG(pixels, width: width, height: height)
            let number = lock.withLock { observations.count + 1 }
            let name = String(format: "frame-%04d.png", number)
            guard ProcessBirth.read(options.pid) == birth else {
                throw CaptureFailure.reason("app-birth-changed-before-frame-write")
            }
            try output.writePNG(png, name: name)
            guard ProcessBirth.read(options.pid) == birth else {
                throw CaptureFailure.reason("app-birth-changed-after-frame-write")
            }
            let gap = previous.map { displaySeconds - $0.displayUptimeSeconds }
            let observation = FrameObservation(number: number, png: name, displayTimeMachTicks: rawTicks,
                displayUptimeSeconds: displaySeconds, callbackReceiptUptimeSeconds: receipt,
                gapFromPreviousCompleteSeconds: gap, width: width, height: height,
                rawPixelSHA256: Self.digest(pixels), pngSHA256: Self.digest(png), pngByteCount: png.count,
                scaleFactor: Self.numeric(metadata[.scaleFactor]), contentScale: Self.numeric(metadata[.contentScale]))
            lock.withLock {
                observations.append(observation)
                maximumGap = max(maximumGap, gap ?? 0)
            }
            if number == options.maximumFrames { fail("frame-limit") }
        } catch let CaptureFailure.reason(reason) { fail(reason) }
        catch { fail("frame-processing-failed") }
        // No CMSampleBuffer, CVPixelBuffer or IOSurface is retained after this callback.
    }

    private func copyPixels(_ buffer: CVPixelBuffer) throws -> (Data, Int, Int) {
        let width = CVPixelBufferGetWidth(buffer); let height = CVPixelBufferGetHeight(buffer)
        guard width > 0, height > 0, width == configuredWidth, height == configuredHeight,
              width <= options.maximumPixels / height,
              CVPixelBufferGetPixelFormatType(buffer) == kCVPixelFormatType_32BGRA,
              !CVPixelBufferIsPlanar(buffer), CVPixelBufferGetDataSize(buffer) <= 32 * 1_048_576 else {
            throw CaptureFailure.reason("pixel-limit-or-format-mismatch")
        }
        guard CVPixelBufferLockBaseAddress(buffer, .readOnly) == kCVReturnSuccess else {
            throw CaptureFailure.reason("pixel-buffer-lock-failed")
        }
        defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
        let rowBytes = width * 4
        let stride = CVPixelBufferGetBytesPerRow(buffer)
        guard stride >= rowBytes, stride <= rowBytes + 4096,
              stride <= CVPixelBufferGetDataSize(buffer) / height,
              let base = CVPixelBufferGetBaseAddress(buffer) else { throw CaptureFailure.reason("invalid-pixel-layout") }
        var pixels = Data(); pixels.reserveCapacity(rowBytes * height)
        for row in 0..<height {
            pixels.append(base.advanced(by: row * stride).assumingMemoryBound(to: UInt8.self), count: rowBytes)
        }
        return (pixels, width, height)
    }

    private func makePNG(_ pixels: Data, width: Int, height: Int) throws -> Data {
        guard let provider = CGDataProvider(data: pixels as CFData),
              let space = CGColorSpace(name: CGColorSpace.sRGB),
              let image = CGImage(width: width, height: height, bitsPerComponent: 8, bitsPerPixel: 32,
                bytesPerRow: width * 4, space: space,
                bitmapInfo: [.byteOrder32Little, CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedFirst.rawValue)],
                provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent) else {
            throw CaptureFailure.reason("png-image-creation-failed")
        }
        let encoded = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(encoded as CFMutableData, UTType.png.identifier as CFString, 1, nil) else {
            throw CaptureFailure.reason("png-destination-failed")
        }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination), encoded.length <= 32 * 1_048_576 else {
            throw CaptureFailure.reason("png-encoding-limit-or-failure")
        }
        return encoded as Data
    }

    func fail(_ reason: String) {
        let first = lock.withLock { () -> Bool in
            guard failureReason == nil else { return false }
            failureReason = reason; return true
        }
        if first { stop.yield(()) }
    }

    func sealAndDrain() async {
        await withCheckedContinuation { continuation in
            queue.async {
                self.lock.withLock { self.accepting = false }
                continuation.resume()
            }
        }
        stop.finish()
    }

    func snapshot() -> (frames: [FrameObservation], statuses: [String: Int], reason: String?, maximumGap: Double) {
        lock.withLock { (observations, statuses, failureReason, maximumGap) }
    }

    private func count(_ key: String) {
        lock.withLock { if let value = statuses[key], value < Int.max { statuses[key] = value + 1 } }
    }
    private static func numeric(_ value: Any?) -> Double? {
        guard let number = value as? NSNumber else { return nil }
        let result = number.doubleValue
        return result.isFinite && result >= 0 && result <= 16 ? result : nil
    }
    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

@main
private enum GUIFrameCaptureMain {
    @MainActor
    static func main() async {
        do { Darwin.exit(try await run(Array(CommandLine.arguments.dropFirst()))) }
        catch let CaptureFailure.reason(reason) {
            emit(["status": reason == "screen-capture-permission-not-present" ? "BLOCKED" : "FAILED", "reason": reason])
            Darwin.exit(reason == "screen-capture-permission-not-present" ? 77 : 64)
        } catch {
            emit(["status": "FAILED", "reason": "capture-failed"])
            Darwin.exit(69)
        }
    }

    @MainActor
    private static func validateApplication(_ options: CaptureOptions,
                                            sameAs original: ApplicationIdentity? = nil) throws -> ApplicationIdentity {
        guard let running = NSRunningApplication(processIdentifier: options.pid), !running.isTerminated,
              let bundle = running.bundleURL?.standardizedFileURL.resolvingSymlinksInPath(),
              bundle == options.appBundle,
              let expectedIdentifier = Bundle(url: options.appBundle)?.bundleIdentifier,
              running.bundleIdentifier == expectedIdentifier,
              let launchDate = running.launchDate, launchDate.timeIntervalSince1970.isFinite,
              let birth = ProcessBirth.read(options.pid) else {
            throw CaptureFailure.reason("app-identity-mismatch")
        }
        let identity = ApplicationIdentity(launchDate: launchDate, birth: birth)
        guard original == nil || identity == original else { throw CaptureFailure.reason("app-birth-mismatch") }
        return identity
    }

    @MainActor
    private static func run(_ arguments: [String]) async throws -> Int32 {
        let options = try CaptureOptions(arguments)
        let original = try validateApplication(options)
        // Preflight does not prompt. Do not enumerate content until permission already exists.
        guard CGPreflightScreenCaptureAccess() else { throw CaptureFailure.reason("screen-capture-permission-not-present") }
        let available = try await SCShareableContent.excludingDesktopWindows(true, onScreenWindowsOnly: true)
        _ = try validateApplication(options, sameAs: original)
        let owned = available.windows.filter { $0.owningApplication?.processID == options.pid && $0.isOnScreen }
        guard available.displays.count <= 16, owned.count <= 64,
              available.displays.allSatisfy({ isValidRect($0.frame) }),
              owned.allSatisfy({ isValidRect($0.frame) }) else { throw CaptureFailure.reason("inventory-limit-or-invalid-geometry") }
        if options.listOwned {
            _ = try validateApplication(options, sameAs: original)
            let displays: [[String: Any]] = available.displays.map { display in
                ["displayID": display.displayID, "framePoints": rectangleJSON(display.frame)]
            }
            let windows: [[String: Any]] = owned.map { window in
                ["windowID": window.windowID, "framePoints": rectangleJSON(window.frame),
                 "containingDisplayIDs": available.displays.filter { $0.frame.contains(window.frame) }.map(\.displayID)]
            }
            emit(["status": "OWNED", "pid": options.pid, "pidBirthSeconds": original.birth.seconds,
                  "pidBirthMicroseconds": original.birth.microseconds, "launchDateUnixSeconds": original.launchDate.timeIntervalSince1970,
                  "syntheticOnly": true, "windows": windows, "displays": displays])
            return 0
        }
        guard let windowID = options.windowID, let displayID = options.displayID, let destination = options.output,
              let window = owned.first(where: { $0.windowID == windowID }),
              let display = available.displays.first(where: { $0.displayID == displayID }),
              isValidRect(window.frame), isValidRect(display.frame), display.frame.contains(window.frame) else {
            throw CaptureFailure.reason("owned-window-display-mismatch")
        }
        let filter = SCContentFilter(display: display, including: [window])
        if #available(macOS 14.2, *) { filter.includeMenuBar = false }
        let scale = Double(filter.pointPixelScale)
        let rect = window.frame.offsetBy(dx: -display.frame.minX, dy: -display.frame.minY)
        guard scale.isFinite, scale >= 1, scale <= 4, isValidRect(rect) else { throw CaptureFailure.reason("invalid-scale-or-crop") }
        let widthValue = ceil(Double(rect.width) * scale); let heightValue = ceil(Double(rect.height) * scale)
        guard widthValue >= 1, heightValue >= 1, widthValue <= Double(options.maximumPixels),
              heightValue <= Double(options.maximumPixels), widthValue * heightValue <= Double(options.maximumPixels) else {
            throw CaptureFailure.reason("configured-pixel-limit")
        }
        let width = Int(widthValue); let height = Int(heightValue)
        var timebase = mach_timebase_info_data_t()
        guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.numer > 0, timebase.denom > 0 else {
            throw CaptureFailure.reason("mach-timebase-unavailable")
        }
        let output = try ExclusiveOutput(url: destination, maximumBytes: options.maximumBytes)
        let (stopEvents, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let recorder = CaptureRecorder(output: output, options: options, width: width, height: height,
                                       timebase: timebase, birth: original.birth, stop: continuation)
        let configuration = SCStreamConfiguration()
        configuration.sourceRect = rect
        configuration.width = width; configuration.height = height
        configuration.pixelFormat = kCVPixelFormatType_32BGRA
        configuration.colorSpaceName = CGColorSpace.sRGB
        configuration.minimumFrameInterval = .zero
        configuration.queueDepth = 3
        configuration.capturesAudio = false
        configuration.showsCursor = false
        let stream = SCStream(filter: filter, configuration: configuration, delegate: recorder)
        try stream.addStreamOutput(recorder, type: .screen, sampleHandlerQueue: recorder.queue)
        _ = try validateApplication(options, sameAs: original)
        let started = CACurrentMediaTime()
        do {
            try await stream.startCapture()
            _ = try validateApplication(options, sameAs: original)
            emit(["status": "READY", "pid": options.pid, "windowID": windowID, "displayID": displayID,
                  "pidBirthSeconds": original.birth.seconds, "pidBirthMicroseconds": original.birth.microseconds,
                  "width": width, "height": height, "pointPixelScale": scale,
                  "maximumDurationSeconds": options.seconds, "maximumFrames": options.maximumFrames,
                  "maximumOutputBytes": options.maximumBytes, "syntheticOnly": true])
            // This deadline only stops capture. It never manufactures a frame or presentation timestamp.
            await withTaskGroup(of: Void.self) { group in
                group.addTask { var iterator = stopEvents.makeAsyncIterator(); _ = await iterator.next() }
                let remaining = max(0, options.seconds - (CACurrentMediaTime() - started))
                group.addTask { try? await Task.sleep(for: .seconds(remaining)) }
                _ = await group.next(); group.cancelAll()
            }
        } catch let CaptureFailure.reason(reason) { recorder.fail(reason) }
        catch { recorder.fail("capture-start-failed") }
        do { _ = try validateApplication(options, sameAs: original) }
        catch { recorder.fail("app-identity-changed-before-stop") }
        do { try await stream.stopCapture() }
        catch { recorder.fail("capture-stop-failed") }
        await recorder.sealAndDrain()
        do { _ = try validateApplication(options, sameAs: original) }
        catch { recorder.fail("app-identity-changed-during-capture") }
        let stopped = CACurrentMediaTime()
        let result = recorder.snapshot()
        let reason = result.reason ?? (result.frames.isEmpty ? "no-complete-frames" : nil)
        let report = CaptureReport(pid: options.pid, windowID: windowID, displayID: displayID,
            pidBirthSeconds: original.birth.seconds, pidBirthMicroseconds: original.birth.microseconds,
            launchDateUnixSeconds: original.launchDate.timeIntervalSince1970,
            sourceRectPoints: NumericRect(rect), pointPixelScale: scale, configuredWidth: width, configuredHeight: height,
            maximumFrames: options.maximumFrames, maximumPixels: options.maximumPixels,
            maximumOutputBytes: options.maximumBytes, maximumDurationSeconds: options.seconds,
            machTimebaseNumerator: timebase.numer, machTimebaseDenominator: timebase.denom,
            startReceiptUptimeSeconds: started, stopReceiptUptimeSeconds: stopped,
            outcome: reason == nil ? "complete" : "partial", reason: reason, outputPNGBytes: output.bytesWritten,
            statusCounts: result.statuses, maximumObservedCompleteGapSeconds: result.maximumGap, frames: result.frames)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(report)
        try output.writeSummary(encoded)
        emit(["status": reason == nil ? "COMPLETE" : "PARTIAL", "frames": result.frames.count,
              "outputTotalBytes": output.bytesWritten, "reason": reason ?? "duration-reached"])
        return reason == nil ? 0 : 2
    }

    private static func isValidRect(_ rect: CGRect) -> Bool {
        rect.origin.x.isFinite && rect.origin.y.isFinite && rect.width.isFinite && rect.height.isFinite
            && rect.width > 0 && rect.height > 0
    }
    private static func rectangleJSON(_ rect: CGRect) -> [String: Double] {
        ["x": Double(rect.minX), "y": Double(rect.minY), "width": Double(rect.width), "height": Double(rect.height)]
    }
    private static func emit(_ value: [String: Any]) {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), data.count <= 65_536 else {
            FileHandle.standardOutput.write(Data("{\"status\":\"FAILED\",\"reason\":\"stdout-receipt-limit\"}\n".utf8))
            return
        }
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
    }
}
