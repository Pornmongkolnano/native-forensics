import CryptoKit
import Darwin
import Foundation

public enum ImageInspector {
    /// Reads only the selected regular file. An E01 hash covers that segment's
    /// container bytes, not its decompressed disk or any other EWF segments.
    public static func inspect(
        url: URL,
        progress: @escaping @Sendable (InspectionProgress) -> Void
    ) async throws -> InspectedImage {
        try Task.checkCancellation()
        let worker = Task.detached(priority: .userInitiated) {
            try inspectFile(url: url, progress: progress)
        }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
    }

    private static func inspectFile(
        url: URL,
        progress: @Sendable (InspectionProgress) -> Void
    ) throws -> InspectedImage {
        try Task.checkCancellation()
        let canonicalURL = try FileAccess.localURL(url)
        let descriptor = try FileAccess.openReadOnly(canonicalURL)
        defer { Darwin.close(descriptor) }
        let original = try FileAccess.identity(of: descriptor)

        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        var header = Data()
        var bytesRead: Int64 = 0
        let clock = ContinuousClock()
        var lastUpdate = clock.now
        progress(InspectionProgress(bytesRead: 0, totalBytes: original.size, fraction: original.size == 0 ? 1 : 0))

        // The original size bounds the read even if another process grows a file.
        while bytesRead < original.size {
            try Task.checkCancellation()
            let requested = Int(min(Int64(buffer.count), original.size - bytesRead))
            let count = try buffer.withUnsafeMutableBytes {
                try FileAccess.read(descriptor, into: $0, count: requested)
            }
            guard count > 0 else { throw ForensicsError.sourceChanged }
            buffer.withUnsafeBytes { bytes in
                hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: bytes[..<count]))
                if header.count < 4096 {
                    header.append(contentsOf: bytes.bindMemory(to: UInt8.self).prefix(min(count, 4096 - header.count)))
                }
            }
            bytesRead += Int64(count)
            let now = clock.now
            if bytesRead == original.size || lastUpdate.duration(to: now) >= .milliseconds(100) {
                progress(InspectionProgress(
                    bytesRead: bytesRead,
                    totalBytes: original.size,
                    fraction: Double(bytesRead) / Double(original.size)
                ))
                lastUpdate = now
            }
        }

        try Task.checkCancellation()
        guard try FileAccess.identity(of: descriptor) == original else { throw ForensicsError.sourceChanged }
        // fstat alone cannot detect the pathname being replaced while the old
        // descriptor is still readable. Validate both the handle and its path.
        guard (try? FileAccess.identity(at: canonicalURL)) == original else { throw ForensicsError.sourceChanged }
        let container = detectContainer(header, url: canonicalURL)
        var result = InspectedImage(
            sourceURL: canonicalURL,
            byteCount: bytesRead,
            sha256: hasher.finalize().map { String(format: "%02x", $0) }.joined(),
            container: container,
            filesystemHint: container == .ewf ? nil : filesystemHint(header)
        )
        result.sourceIdentity = original
        try Task.checkCancellation()
        return result
    }

    private static func detectContainer(_ header: Data, url: URL) -> ImageContainer {
        let magic = Array(header.prefix(8))
        let ewfMagics: [[UInt8]] = [
            [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00],
            [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00],
            [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00],
            [0x4c, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00]
        ]
        if ewfMagics.contains(magic) { return .ewf }
        if ["dd", "img", "raw"].contains(url.pathExtension.lowercased()) || filesystemHint(header) != nil { return .raw }
        return .unknown
    }

    private static func filesystemHint(_ header: Data) -> String? {
        // These are lightweight signatures, not validated filesystem parsers.
        func matches(_ offset: Int, _ value: String) -> Bool {
            let pattern = Data(value.utf8)
            guard offset >= 0, header.count >= offset + pattern.count else { return false }
            return header.subdata(in: offset..<(offset + pattern.count)) == pattern
        }
        if matches(3, "NTFS    ") { return "NTFS boot-sector signature" }
        if matches(3, "EXFAT   ") { return "exFAT boot-sector signature" }
        if matches(54, "FAT12   ") { return "FAT12 boot-sector signature" }
        if matches(54, "FAT16   ") { return "FAT16 boot-sector signature" }
        if matches(82, "FAT32   ") { return "FAT32 boot-sector signature" }
        if matches(32, "NXSB") { return "APFS container signature" }
        if matches(512, "EFI PART") { return "GPT partition-table signature" }
        if matches(1024, "H+") { return "HFS+ volume signature" }
        if matches(1024, "HX") { return "HFSX volume signature" }
        return nil
    }
}
