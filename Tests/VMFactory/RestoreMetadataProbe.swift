import CryptoKit
import Foundation
@preconcurrency import Virtualization

// Standalone laboratory planner, outside the app and SwiftPM test targets.
// It obtains only Apple's restore metadata and an HTTP HEAD response. It never
// downloads an IPSW, creates a disk/VM, or opens an existing user VM.
@main
struct RestoreMetadataProbe {
    private static let gib: UInt64 = 1_073_741_824

    struct Plan: Encodable {
        let schemaVersion = 1
        let operation = "metadata-only-no-vm-or-restore-download"
        let hostOS: String
        let physicalMemoryBytes: UInt64
        let freeStorageBytes: UInt64
        let restoreURL: String
        let restoreBuild: String
        let restoreOS: String
        let expectedRestoreBytes: UInt64
        let maximumRestoreBytes: UInt64
        let restoreWithinDownloadBudget: Bool
        let headFinalURL: String
        let headObservedAt: String
        let headETag: String?
        let headLastModified: String?
        let minimumCPUCount: Int
        let minimumMemoryBytes: UInt64
        let selectedCPUCount: Int
        let selectedMemoryBytes: UInt64
        let guestLogicalDiskBytes: UInt64
        let workingStorageBudgetBytes: UInt64
        let minimumFreeReserveBytes: UInt64
        let sparseAndCOWPlanRequiredBytes: UInt64
        let sparseAndCOWPlanFits: Bool
        let completeResourcePreflightFits: Bool
        let twoIndependentFullCopiesRequiredBytes: UInt64
        let twoIndependentFullCopiesFit: Bool
        let acquisitionRequiresOwnedCOWClone: Bool
        let streamingCopyFallbackAuthorized: Bool
        let existingMacOSGuestCount: Int?
        let existingGuestAllowanceMustBeConfirmed: Bool
        let hostLicenseAcquisitionBasis: String
        let hostLicenseSHA256: String
        let vmCreationAuthorizedByThisProbe: Bool
    }

    enum ProbeError: Error {
        case invalidArguments, unsupportedHost, incompatibleRestore, nonAppleRestoreURL
        case noBoundedRestoreLength, restoreTooLarge, insufficientMemory, insufficientCPUs
        case storageUnavailable, licenseUnavailable, unexpectedResponseBody
    }

    @MainActor
    static func main() async {
        do {
            #if arch(arm64)
            guard CommandLine.arguments.count == 2 else { throw ProbeError.invalidArguments }
            let storagePath = CommandLine.arguments[1]
            let fs = try FileManager.default.attributesOfFileSystem(forPath: storagePath)
            guard let number = fs[.systemFreeSize] as? NSNumber else { throw ProbeError.storageUnavailable }
            let free = number.uint64Value
            guard VZVirtualMachine.isSupported else { throw ProbeError.unsupportedHost }

            let restore = try await VZMacOSRestoreImage.latestSupported
            guard restore.isSupported, let requirements = restore.mostFeaturefulSupportedConfiguration,
                  requirements.hardwareModel.isSupported else { throw ProbeError.incompatibleRestore }
            guard isAppleHTTPS(restore.url), restore.url.path.lowercased().hasSuffix(".ipsw") else {
                let diagnostic = ["reason": "restoreURLRejected", "scheme": restore.url.scheme ?? "absent",
                                  "host": String((restore.url.host ?? "absent").prefix(256)),
                                  "pathExtension": restore.url.pathExtension]
                if let encoded = try? JSONSerialization.data(withJSONObject: diagnostic, options: [.sortedKeys]) {
                    FileHandle.standardError.write(encoded + Data([10]))
                }
                throw ProbeError.nonAppleRestoreURL
            }
            let head = try await restoreLength(restore.url), expectedBytes = head.byteCount
            let memory = max(4 * gib, requirements.minimumSupportedMemorySize)
            guard memory <= 6 * gib, ProcessInfo.processInfo.physicalMemory >= memory + 8 * gib else {
                throw ProbeError.insufficientMemory
            }
            let cpus = max(2, requirements.minimumSupportedCPUCount)
            guard cpus <= 4, cpus <= VZVirtualMachineConfiguration.maximumAllowedCPUCount else {
                throw ProbeError.insufficientCPUs
            }
            let licenseURL = URL(fileURLWithPath: "/Library/Documentation/License.lpdf/Contents/Resources/English.lproj/License.html")
            guard let licenseSize = try FileManager.default.attributesOfItem(atPath: licenseURL.path)[.size] as? NSNumber,
                  licenseSize.uint64Value <= 1_048_576 else { throw ProbeError.licenseUnavailable }
            let license = try Data(contentsOf: licenseURL)
            let version = restore.operatingSystemVersion
            let guestBytes = 50 * gib, workspaceBytes = 8 * gib, reserveBytes = 30 * gib
            let cowRequired = guestBytes + expectedBytes + workspaceBytes + reserveBytes
            let independentRequired = 2 * guestBytes + expectedBytes + workspaceBytes + reserveBytes
            let plan = Plan(hostOS: ProcessInfo.processInfo.operatingSystemVersionString,
                physicalMemoryBytes: ProcessInfo.processInfo.physicalMemory, freeStorageBytes: free,
                restoreURL: restore.url.absoluteString, restoreBuild: restore.buildVersion,
                restoreOS: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
                expectedRestoreBytes: expectedBytes, maximumRestoreBytes: 20 * gib,
                restoreWithinDownloadBudget: expectedBytes <= 20 * gib,
                headFinalURL: head.finalURL, headObservedAt: head.observedAt,
                headETag: head.eTag, headLastModified: head.lastModified,
                minimumCPUCount: requirements.minimumSupportedCPUCount,
                minimumMemoryBytes: requirements.minimumSupportedMemorySize, selectedCPUCount: cpus,
                selectedMemoryBytes: memory, guestLogicalDiskBytes: guestBytes,
                workingStorageBudgetBytes: workspaceBytes, minimumFreeReserveBytes: reserveBytes,
                sparseAndCOWPlanRequiredBytes: cowRequired, sparseAndCOWPlanFits: free >= cowRequired,
                completeResourcePreflightFits: free >= cowRequired && expectedBytes <= 20 * gib,
                twoIndependentFullCopiesRequiredBytes: independentRequired, twoIndependentFullCopiesFit: free >= independentRequired,
                acquisitionRequiresOwnedCOWClone: true, streamingCopyFallbackAuthorized: false,
                existingMacOSGuestCount: nil, existingGuestAllowanceMustBeConfirmed: true,
                hostLicenseAcquisitionBasis: "unverified-Mac-App-Store-or-automatic-download",
                hostLicenseSHA256: digest(license), vmCreationAuthorizedByThisProbe: false)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            let output = try encoder.encode(plan)
            guard output.count <= 16_384 else { throw ProbeError.unexpectedResponseBody }
            FileHandle.standardOutput.write(output + Data([10]))
            #else
            throw ProbeError.unsupportedHost
            #endif
        } catch {
            let failure: String
            if let known = error as? ProbeError { failure = String(describing: known) }
            else { let ns = error as NSError; failure = "system failure domain=\(ns.domain) code=\(ns.code)" }
            FileHandle.standardError.write(Data(("Restore metadata planning failed: " + failure + "\n").utf8))
            exit(1)
        }
    }

    private static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    private static func isAppleHTTPS(_ url: URL) -> Bool {
        guard url.scheme == "https", let host = url.host?.lowercased(),
              host == "apple.com" || host.hasSuffix(".apple.com") || host == "updates.cdn-apple.com",
              url.user == nil, url.password == nil, url.port == nil || url.port == 443 else { return false }
        return true
    }

    private struct HEADMetadata: Sendable {
        let byteCount: UInt64
        let finalURL: String
        let observedAt: String
        let eTag: String?
        let lastModified: String?
    }
    private static func restoreLength(_ url: URL) async throws -> HEADMetadata {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20; configuration.timeoutIntervalForResource = 25
        configuration.urlCache = nil; configuration.httpCookieStorage = nil
        let session = URLSession(configuration: configuration, delegate: AppleRedirectOnly(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url); request.httpMethod = "HEAD"
        let (body, response) = try await session.data(for: request)
        guard body.isEmpty else { throw ProbeError.unexpectedResponseBody }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let responseURL = http.url, isAppleHTTPS(responseURL),
              let declared = http.value(forHTTPHeaderField: "Content-Length"),
              let length = UInt64(declared), length > 0 else { throw ProbeError.noBoundedRestoreLength }
        return .init(byteCount: length, finalURL: responseURL.absoluteString,
            observedAt: ISO8601DateFormatter().string(from: Date()),
            eTag: http.value(forHTTPHeaderField: "ETag").map { String($0.prefix(256)) },
            lastModified: http.value(forHTTPHeaderField: "Last-Modified").map { String($0.prefix(128)) })
    }

    private final class AppleRedirectOnly: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        private let lock = NSLock()
        private var redirects = 0
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            // A redirect must remain HEAD; never turn this planner into an
            // installation-media GET, even if a server suggests that redirect.
            lock.lock(); redirects += 1; let withinLimit = redirects <= 3; lock.unlock()
            completionHandler(withinLimit && request.httpMethod == "HEAD" && request.url.map { isAppleHTTPS($0) } == true ? request : nil)
        }
    }
}
