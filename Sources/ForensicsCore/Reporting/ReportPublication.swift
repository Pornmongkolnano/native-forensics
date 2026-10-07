import Darwin
import Foundation

@_silgen_name("flock")
private func publicationFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

/// Publishes new report files only. The selected evidence and all case storage
/// are excluded; cancellation stops before the synchronized rename boundary.
enum ReportPublication {
    static func publish(_ data: Data, in forensicCase: ForensicCase, to outputURL: URL,
                        validateBinding: @escaping () throws -> Void,
                        beforePublication: () throws -> Void = {}, afterPublication: () -> Void = {}) throws -> URL {
        try Task.checkCancellation()
        guard data.count <= RecoveryReportBuilder.maximumReportBytes, outputURL.isFileURL,
              outputURL.host == nil || outputURL.host == "" || outputURL.host == "localhost",
              !outputURL.path.utf8.contains(0) else { throw RecoveryError.outputLimit }
        let bundle = forensicCase.bundleURL.standardizedFileURL
        let destination = outputURL.standardizedFileURL
        let root = try EvidenceViewFiles.openDirectory(bundle)
        defer { Darwin.close(root) }
        let lock = try FileAccess.openReadOnly(".case.lock", in: root)
        defer { Darwin.close(lock) }
        let lockIdentity = try FileAccess.identity(of: lock)
        var lockInfo = stat()
        guard Darwin.fstat(lock, &lockInfo) == 0, lockInfo.st_nlink == 1 else { throw RecoveryError.storageChanged }
        while publicationFlock(lock, LOCK_SH | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            guard errno == EWOULDBLOCK else { throw FileAccess.posixError("Cannot lock report publication") }
            try Task.checkCancellation(); usleep(10_000)
        }
        defer { _ = publicationFlock(lock, LOCK_UN) }
        let current = try CaseStore.open(at: bundle)
        guard current.manifest == forensicCase.manifest else { throw ForensicsError.staleCase }
        guard !FileAccess.isInside(destination, directory: bundle),
              !current.manifest.evidence.contains(where: {
                  URL(fileURLWithPath: $0.sourcePath).standardizedFileURL.path == destination.path
              }) else { throw RecoveryError.scopeMismatch }
        let manifestIdentity = try FileAccess.identity(at: "manifest.json", in: root)
        let parentURL = destination.deletingLastPathComponent()
        let parent = try EvidenceViewFiles.openDirectory(parentURL)
        defer { Darwin.close(parent) }
        let validate = {
            try EvidenceViewFiles.validateDirectory(bundle, descriptor: root)
            try EvidenceViewFiles.validateDirectory(parentURL, descriptor: parent)
            guard (try? FileAccess.identity(at: ".case.lock", in: root)) == lockIdentity,
                  (try? FileAccess.identity(at: "manifest.json", in: root)) == manifestIdentity else {
                throw RecoveryError.storageChanged
            }
            try validateBinding()
        }
        try validate()
        let staging = ".native-report-\(UUID().uuidString.lowercased()).tmp"
        let descriptor = Darwin.openat(parent, staging, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot stage report") }
        defer {
            if EvidenceViewFiles.referenceMatches(staging, parent: parent, descriptor: descriptor) {
                _ = Darwin.unlinkat(parent, staging, 0)
            }
            Darwin.close(descriptor)
        }
        try data.withUnsafeBytes { buffer in
            var written = 0
            while written < buffer.count {
                try Task.checkCancellation()
                let count = Darwin.write(descriptor, buffer.baseAddress?.advanced(by: written), min(65_536, buffer.count - written))
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FileAccess.posixError("Cannot write report") }
                written += count
            }
        }
        guard Darwin.fsync(descriptor) == 0 else { throw FileAccess.posixError("Cannot flush report") }
        let identity = try FileAccess.identity(of: descriptor)
        try beforePublication()
        try validate()
        guard identity.size == Int64(data.count), try FileAccess.identity(of: descriptor) == identity,
              EvidenceViewFiles.referenceMatches(staging, parent: parent, descriptor: descriptor) else {
            throw RecoveryError.storageChanged
        }
        // Re-read the bounded stage so a changed or short staged response can
        // never be published as the originally rendered report.
        var buffer = [UInt8](repeating: 0, count: 65_536), offset = 0
        while offset < data.count {
            try Task.checkCancellation()
            let amount = min(buffer.count, data.count - offset)
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(descriptor, $0.baseAddress, amount, off_t(offset)) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0, Data(buffer.prefix(count)) == data.subdata(in: offset..<offset + count) else {
                throw RecoveryError.storageChanged
            }
            offset += count
        }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_nlink == 1,
              try FileAccess.identity(of: descriptor) == identity else { throw RecoveryError.storageChanged }
        try Task.checkCancellation()
        guard Darwin.renameatx_np(parent, staging, parent, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw RecoveryError.destinationExists }
            throw FileAccess.posixError("Cannot publish report")
        }
        afterPublication()
        guard Darwin.fsync(parent) == 0 else { throw FileAccess.posixError("Cannot flush report directory") }
        // Do not perform a cancellation-sensitive binding reread after commit.
        return destination
    }
}
