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
        try await inspect(url: url, progress: progress,
                          readForTesting: { try FileAccess.read($0, into: $1, count: $2) })
    }

    /// Per-call internal fault seam. Production always supplies the real reader;
    /// tests can fail an exact read after observing real source bytes. It changes
    /// neither source ownership nor identity/hash/publication checks.
    typealias ReadForTesting = @Sendable (Int32, UnsafeMutableRawBufferPointer, Int) throws -> Int

    static func inspect(
        url: URL,
        progress: @escaping @Sendable (InspectionProgress) -> Void,
        readForTesting: @escaping ReadForTesting,
        descriptorClosedForTesting: @escaping @Sendable (Int32, Int32) -> Void = { _, _ in }
    ) async throws -> InspectedImage {
        try Task.checkCancellation()
        let priority = ForensicWorkExecutionContext.requestedTaskPriority
        let worker = Task.detached(priority: priority) {
            try inspectFile(url: url, progress: progress, read: readForTesting, descriptorClosed: descriptorClosedForTesting)
        }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
    }

    private static func inspectFile(
        url: URL,
        progress: @Sendable (InspectionProgress) -> Void,
        read: ReadForTesting,
        descriptorClosed: @Sendable (Int32, Int32) -> Void
    ) throws -> InspectedImage {
        try Task.checkCancellation()
        let canonicalURL = try FileAccess.localURL(url)
        let descriptor = try FileAccess.openReadOnly(canonicalURL)
        defer {
            let status = Darwin.close(descriptor)
            descriptorClosed(descriptor, status)
        }
        let original = try FileAccess.identity(of: descriptor)

        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        var header = Data()
        var footer = Data()
        var bytesRead: Int64 = 0
        let clock = ContinuousClock()
        var lastUpdate = clock.now
        progress(InspectionProgress(bytesRead: 0, totalBytes: original.size, fraction: original.size == 0 ? 1 : 0))

        // The original size bounds the read even if another process grows a file.
        while bytesRead < original.size {
            try Task.checkCancellation()
            let requested = Int(min(Int64(buffer.count), original.size - bytesRead))
            let count = try buffer.withUnsafeMutableBytes {
                try read(descriptor, $0, requested)
            }
            guard count > 0, count <= requested else { throw ForensicsError.sourceChanged }
            buffer.withUnsafeBytes { bytes in
                hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: bytes[..<count]))
                if header.count < 4096 {
                    header.append(contentsOf: bytes.bindMemory(to: UInt8.self).prefix(min(count, 4096 - header.count)))
                }
                // Retain only the final UDIF-sized window from this existing
                // pinned/hash read. No second source read, seek or whole-file
                // allocation is needed to distinguish stored wrapper bytes.
                let retained = min(count, 512)
                if footer.count + retained > 512 { footer.removeFirst(footer.count + retained - 512) }
                footer.append(contentsOf: UnsafeRawBufferPointer(rebasing: bytes[(count - retained)..<count]).bindMemory(to: UInt8.self))
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
        let framing = classify(header: header, footer: footer, byteCount: bytesRead, url: canonicalURL)
        var result = InspectedImage(
            sourceURL: canonicalURL,
            byteCount: bytesRead,
            sha256: hasher.finalize().map { String(format: "%02x", $0) }.joined(),
            container: framing.container,
            filesystemHint: framing.hint
        )
        result.sourceIdentity = original
        try Task.checkCancellation()
        return result
    }

    /// Bounded framing recognition shared with fresh RAW-only consumers. It is
    /// not a UDIF decoder: recognized or malformed framed wrappers stay unknown
    /// and must not acquire linear logical-media offset semantics.
    static func classify(header: Data, footer: Data, byteCount: Int64, url: URL) -> (container: ImageContainer, hint: String?) {
        let magic = Array(header.prefix(8))
        let ewfMagics: [[UInt8]] = [
            [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00],
            [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00],
            [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00],
            [0x4c, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00]
        ]
        if ewfMagics.contains(magic) { return (.ewf, nil) }
        if header.prefix(8) == Data("encrcdsa".utf8) {
            // The independently observed encrypted UDIF v2 image exposes only
            // this public signature/version before ciphertext. Recognition
            // supplies no decryption or logical-media offset semantics. Keep a
            // full signature conservative even when its version is incomplete
            // or unsupported, rather than admitting it through a RAW suffix.
            let version: UInt32? = header.count >= 12 ? header[header.index(header.startIndex, offsetBy: 8)..<header.index(header.startIndex, offsetBy: 12)]
                .reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } : nil
            if byteCount >= 12, version == 2 {
                return (.unknown, "Encrypted UDIF wrapper signature (version 2): \(byteCount) stored bytes. The hash covers stored encrypted container bytes; plaintext media offsets are unavailable.")
            }
            return (.unknown, "Encrypted UDIF wrapper signature has incomplete or unsupported version framing: \(byteCount) stored bytes. Direct RAW byte-offset scanning is unavailable.")
        }
        switch udifFraming(footer, byteCount: byteCount) {
        case .bounded(let logicalBytes):
            return (.unknown, "UDIF disk-image wrapper: \(byteCount) stored bytes, \(logicalBytes) declared logical media bytes. The hash covers stored container bytes.")
        case .malformed:
            return (.unknown, "Malformed UDIF footer framing has invalid size or range metadata; direct RAW byte-offset scanning is unavailable.")
        case .absent:
            let hint = filesystemHint(header)
            if ["dd", "img", "raw"].contains(url.pathExtension.lowercased()) || hint != nil { return (.raw, hint) }
            return (.unknown, hint)
        }
    }

    private enum UDIFFraming { case absent, bounded(Int64), malformed }

    private static func udifFraming(_ footer: Data, byteCount: Int64) -> UDIFFraming {
        guard byteCount >= 512, footer.count == 512, footer.prefix(4) == Data("koly".utf8) else { return .absent }
        func be32(_ offset: Int) -> UInt32 {
            let start = footer.index(footer.startIndex, offsetBy: offset)
            return footer[start..<footer.index(start, offsetBy: 4)].reduce(0) { ($0 << 8) | UInt32($1) }
        }
        func be64(_ offset: Int) -> UInt64 {
            let start = footer.index(footer.startIndex, offsetBy: offset)
            return footer[start..<footer.index(start, offsetBy: 8)].reduce(0) { ($0 << 8) | UInt64($1) }
        }
        guard be32(4) == 4, be32(8) == 512 else { return .absent }
        // UDIF's big-endian footer framing is independently described by the
        // pinned primary go-apfs-v2 DMGFooter source. Bounds distinguish a
        // plausible wrapper, without parsing its plist/chunks/checksums or
        // allocating its declared logical disk.
        let sectors = be64(492), storedLimit = UInt64(byteCount - 512)
        guard sectors > 0, sectors <= UInt64(Int64.max) / 512 else { return .malformed }
        func rangeFits(_ offset: UInt64, _ length: UInt64) -> Bool {
            offset <= storedLimit && length <= storedLimit - offset
        }
        let dataOffset = be64(24), dataLength = be64(32)
        let resourceOffset = be64(40), resourceLength = be64(48)
        let plistOffset = be64(216), plistLength = be64(224)
        guard rangeFits(dataOffset, dataLength), rangeFits(resourceOffset, resourceLength),
              rangeFits(plistOffset, plistLength), plistLength > 0 || resourceLength > 0 else { return .malformed }
        return .bounded(Int64(sectors * 512))
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
