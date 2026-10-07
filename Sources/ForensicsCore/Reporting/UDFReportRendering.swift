import Foundation

/// Internal presentation only. The public writer validates case/job/content
/// bindings before calling this renderer and owns publication of the report.
enum UDFReportRendering {
    static func render(result: UDFInspectionResult, analyses: [String: DocumentAnalysis]) -> String {
        var report = BoundedReport()
        let current = result.entries.filter { $0.state == .current }
        let historical = result.entries.filter { $0.state != .current }
        report.append([
            "# UDF namespace and history report", "",
            "- Case ID: \(result.caseID.uuidString.lowercased())",
            "- Evidence ID: \(result.sourceEvidenceID.uuidString.lowercased())",
            "- Inspection job ID: \(result.jobID.uuidString.lowercased())",
            "- Schema version: \(result.schemaVersion)",
            "- Selected raw source SHA-256: \(safe(result.sourceSHA256, limit: 64))",
            "- Selected raw source size: \(result.sourceByteCount) bytes",
            "- Source hash scope: every byte of the selected raw source file (\(FileHashScope.selectedFileBytes))",
            "- Source offsets: absolute byte offsets in that selected raw source; entry SHA-256 covers logical file bytes assembled from its recorded source extents",
            "- Parser version: \(safe(result.parserVersion, limit: 128))",
            "- Supported inspection profile: \(safe(result.profile, limit: 256))",
            "- UDF revision: \(safe(result.udfRevision, limit: 64)); volume identifier: \(safe(result.volumeIdentifier, limit: 1_024)); logical block size: \(result.blockSize) bytes",
            "- Latest linked snapshot ID: \(safe(result.latestSnapshotID, limit: 256))",
            "- Recorded snapshots: \(result.snapshots.count); current file entries: \(current.count); historical file entries: \(historical.count)",
            "- Receipt saved at: \(utc(result.savedAt))", "",
            "Status: a saved result from the bounded profile shown above. This is a recorded namespace/VAT inspection, not a claim of complete or general UDF support. Missing files or snapshots outside the supported profile and inspection bounds remain unknown.", "",
            "Source and entry hashes/extents are inspection-time provenance. This report can be produced from stored receipts with the source offline; it does not reopen or freshly rehash the source, repeat inspection or freshly verify extent bytes. Stored case/job receipt binding is validated by the report writer. A matching byte/hash receipt does not establish decoder accessibility, document readability or deletion.", "",
            "Current and historical rows are reported separately. FID-deleted is an observation of the child's own FID deleted bit (0x04). Historical-deleted-ancestor is an inference from retained namespace history and a latest-snapshot ancestor proof; it does not mean that the child FID is itself deleted. Historical alone does not prove deletion.", "",
            "Filesystem timestamp records retain their raw fields and absolute source offsets. UTC dates are displayed only when the parser recorded a UTC date; an unknown or unspecified time zone stays unknown. No host time zone is substituted. EXIF and other document dates are raw metadata, separate from UDF filesystem dates.", "",
            "Decoder MIME is an independent content observation; the original filename extension is only a namespace hint. Container/Office structure recognition does not prove that an unsupported document body is readable. Text coverage is limited to returned PDF pages, Office body/slide/sheet references, text units or ZIP members. No OCR, embedded-image search or unreturned-unit coverage is implied. Report text excerpts are bounded; payloads and thumbnails are excluded.", "",
            "## Inspection bounds and limitations", "",
            "- Maximum source bytes: \(result.options.maximumSourceBytes)",
            "- Maximum snapshots/files: \(result.options.maximumSnapshots)/\(result.options.maximumFiles)",
            "- Maximum file/payload bytes: \(result.options.maximumFileBytes)/\(result.options.maximumPayloadBytes)",
            "- Maximum metadata blocks/directory bytes: \(result.options.maximumMetadataBlocks)/\(result.options.maximumDirectoryBytes)",
            "- Tail search blocks: \(result.options.tailSearchBlocks); timeout: \(result.options.timeoutSeconds) seconds",
        ])
        if result.limitations.isEmpty {
            report.append(["- No additional limitations were recorded by this result; the profile and bounds still apply.", ""])
        } else {
            report.append(result.limitations.map { "- " + safe($0, limit: 4_096) } + [""])
        }

        report.append(["## Recorded VAT snapshots", "",
            "| Snapshot ID | Latest | VAT ICB source offset | Previous VAT logical block | Mapped blocks | Namespace files | Modification UTC |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- |"])
        // Preserve every recorded snapshot instead of assuming an assignment's
        // snapshot count. Validated results contain at most 32 snapshots.
        for snapshot in result.snapshots {
            report.append(["| \(safe(snapshot.id, limit: 256)) | \(snapshot.id == result.latestSnapshotID ? "yes" : "no") | \(snapshot.vatICBSourceOffset) | \(snapshot.previousVATLogicalBlock.map(String.init) ?? "none recorded") | \(snapshot.mappedBlockCount) | \(snapshot.namespaceFileCount) | \(snapshot.modification.utcDate.map(utc) ?? "unknown") |"])
        }
        report.append(["", "### Raw snapshot timestamp records", ""])
        for snapshot in result.snapshots {
            report.append(["- Snapshot \(safe(snapshot.id, limit: 256)): \(timestamp(snapshot.modification))"])
        }
        report.append([""])
        inventory(title: "Current namespace file inventory", entries: current, analyses: analyses, report: &report)
        inventory(title: "Historical namespace file inventory", entries: historical, analyses: analyses, report: &report)

        report.append(["## Latest-snapshot deleted ancestor observations", "",
            "These directory observations bind the raw FID flags/name and null-ICB observation to the latest snapshot. A directory FID value of 0x06 combines directory (0x02) and deleted (0x04) bits. It is not a statement about any child's own FID flags.", "",
            "| Original ancestor path | Latest snapshot ID | FID source offset | FID flags | Own deleted bit | Null ICB | Raw name hex |",
            "| --- | --- | ---: | --- | --- | --- | --- |"])
        if result.deletedAncestors.isEmpty { report.append(["No deleted ancestor proofs were recorded."]) }
        var omittedProofs = 0
        for proof in result.deletedAncestors {
            if !report.append(["| \(safe(proof.originalPath, limit: 256, redactHostPaths: false)) | \(safe(proof.latestSnapshotID, limit: 256)) | \(proof.fidSourceOffset) | \(flags(proof.fidCharacteristics)) | \(deleted(proof.fidCharacteristics)) | \(proof.nullICB ? "yes" : "no") | \(safe(proof.rawNameHex, limit: 512)) |"], reserve: 2_048) {
                omittedProofs += 1
            }
        }
        report.append(["", "Deleted ancestor table rows omitted by the report byte bound: \(omittedProofs). Complete raw records remain in the saved result.", ""], reserve: 1_024)

        report.append(["## Entry addresses, timestamps and decoder observations", ""], reserve: 1_024)
        var omittedEntries = 0
        for entry in result.entries {
            if !report.append(observations(entry: entry, analysis: analyses[entry.id]), reserve: 1_024) {
                omittedEntries += 1
            }
        }
        report.append(["", "Detailed entry sections omitted by the report byte bound: \(omittedEntries). Inventory row omissions and individually bounded excerpts are stated separately. Open the saved case result for complete receipts.", ""], reserve: 256)
        return report.finish()
    }

    private static func inventory(title: String, entries: [UDFFileEntry],
                                  analyses: [String: DocumentAnalysis], report: inout BoundedReport) {
        report.append(["## \(title)", "",
            "| Entry ID | Original namespace path | Classification | Child FID flags | Child own deleted bit | FID source offset | Bytes | Logical SHA-256 | Original extension | Decoder MIME | Decoder status |",
            "| --- | --- | --- | --- | --- | ---: | ---: | --- | --- | --- | --- |"], reserve: 2_048)
        if entries.isEmpty { report.append(["No entries in this category.", ""], reserve: 2_048) }
        var omitted = 0
        for entry in entries {
            let analysis = analyses[entry.id]
            let ext = (entry.originalPath as NSString).pathExtension
            let row = "| \(safe(entry.id, limit: 256)) | \(safe(entry.originalPath, limit: 256, redactHostPaths: false)) | \(entry.state.rawValue) | \(flags(entry.fidCharacteristics)) | \(deleted(entry.fidCharacteristics)) | \(entry.fidSourceOffset) | \(entry.byteCount) | \(safe(entry.sha256, limit: 64)) | \(ext.isEmpty ? "none" : safe(ext, limit: 64)) | \(analysis.map { safe($0.mimeType, limit: 128) } ?? "unknown (not analyzed)") | \(analysis?.status.rawValue ?? "unknown (not analyzed)") |"
            if !report.append([row], reserve: 2_048) { omitted += 1 }
        }
        report.append(["", "Inventory: \(entries.count) recorded entries; \(omitted) rows omitted by the report byte bound. Namespace paths and extensions may be excerpted; source offsets/IDs bind rows to saved records.", ""], reserve: 1_024)
    }

    private static func observations(entry: UDFFileEntry, analysis: DocumentAnalysis?) -> [String] {
        var lines = ["### Entry \(safe(entry.id, limit: 256))", "",
            "Original namespace path: \(safe(entry.originalPath, limit: 1_024, redactHostPaths: false))",
            "Classification: \(entry.state.rawValue); child's FID flags: \(flags(entry.fidCharacteristics)); child's own deleted bit: \(deleted(entry.fidCharacteristics)); FID absolute source offset: \(entry.fidSourceOffset).",
            "Logical file bytes: \(entry.byteCount); SHA-256: \(safe(entry.sha256, limit: 64)).",
            "ICB address: logical block \(entry.icb.logicalBlock), partition reference \(entry.icb.partitionReference), absolute source offset \(entry.icb.sourceOffset), tag identifier \(entry.icb.tagIdentifier).",
            "Recorded snapshot IDs: \(list(entry.snapshotIDs, limit: 256, count: 32))",
            "Other recorded namespace paths: \(list(entry.historicalPaths, limit: 512, count: 32, redactHostPaths: false))", "",
            "Recorded source extents (absolute offset + byte count, in logical-file assembly order):"]
        for extent in entry.sourceExtents.prefix(64) {
            lines.append("- \(extent.offset) + \(extent.byteCount) bytes; allocation: \(safe(extent.allocation, limit: 128))")
        }
        if entry.sourceExtents.isEmpty { lines.append("- No extents (empty logical file).") }
        if entry.sourceExtents.count > 64 { lines.append("- \(entry.sourceExtents.count - 64) additional extents omitted; see the saved entry receipt.") }
        lines += ["", "Filesystem timestamp records:",
            "- Access: \(timestamp(entry.timestamps.access))",
            "- Modification: \(timestamp(entry.timestamps.modification))",
            "- Attribute change: \(timestamp(entry.timestamps.attribute))",
            "- Creation: \(entry.timestamps.creation.map(timestamp) ?? "not recorded")", ""]
        if !entry.deletedAncestorProof.isEmpty {
            lines += ["Historical deleted-ancestor inference is bound to these directory proofs. These flags are the ancestor's, not the child's:"]
            for proof in entry.deletedAncestorProof.prefix(32) {
                lines.append("- \(safe(proof.originalPath, limit: 512, redactHostPaths: false)); latest snapshot \(safe(proof.latestSnapshotID, limit: 256)); FID offset \(proof.fidSourceOffset); flags \(flags(proof.fidCharacteristics)); own deleted bit \(deleted(proof.fidCharacteristics)); null ICB \(proof.nullICB ? "yes" : "no"); raw name hex \(safe(proof.rawNameHex, limit: 512)).")
            }
            if entry.deletedAncestorProof.count > 32 { lines.append("- \(entry.deletedAncestorProof.count - 32) additional proofs omitted; see the saved result.") }
            lines.append("")
        }
        guard let analysis else {
            return lines + ["Decoder status: unknown (not analyzed). MIME, accessibility, document body text and embedded metadata have not been established.", ""]
        }
        lines += ["Decoder observation: \(analysis.status.rawValue); MIME \(safe(analysis.mimeType, limit: 128)); content kind \(analysis.contentKind.rawValue). The validated decoder receipt matches the logical-file SHA-256 and size."]
        if let code = analysis.failureCode { lines.append("Decoder failure code: \(safe(code, limit: 128)).") }
        if let format = analysis.officeFormat {
            lines.append("Office format: \(format.rawValue); structural validation: \(analysis.structuralValidation?.rawValue ?? "unknown"). A recognized legacy container or signature with unsupported body decoding does not establish readable document content.")
        } else if let structure = analysis.structuralValidation {
            lines.append("Structural validation: \(structure.rawValue).")
        }
        if let width = analysis.pixelWidth, let height = analysis.pixelHeight { lines.append("Image dimensions: \(width) × \(height) pixels.") }
        if let title = analysis.title { lines.append("Decoder title: \(safe(title, limit: 512)).") }
        if !analysis.rawMetadata.isEmpty {
            lines += ["", "Raw file metadata (including EXIF dates; unzoned values remain unzoned):"]
            for item in analysis.rawMetadata.prefix(16) { lines.append("- \(safe(item.name, limit: 128)): \(safe(item.value, limit: 512))") }
            if analysis.rawMetadata.count > 16 { lines.append("- \(analysis.rawMetadata.count - 16) additional raw metadata items omitted.") }
        }
        if [.pdf, .text, .office, .archive].contains(analysis.contentKind) {
            let total = analysis.contentKind == .pdf ? analysis.pageCount : (analysis.contentUnitCount ?? analysis.pageCount)
            lines += ["", "Decoded text scope: \(analysis.textIsComplete ? "complete returned decoded-text coverage" : "partial or unavailable decoded-text coverage"); \(analysis.textPages.count)/\(total.map(String.init) ?? "unknown") units. No OCR. Bounded report excerpts are not a complete body-text export; archive-member text is not proof that every member's body was decoded."]
            for unit in analysis.textPages.prefix(3) {
                let reference = unit.referenceLabel ?? (analysis.contentKind == .pdf ? "Page \(unit.pageNumber)" : "Text unit \(unit.pageNumber)")
                lines += ["", "Reference: \(safe(reference, limit: 256)); reference kind: \(unit.referenceKind?.rawValue ?? "unspecified"); one-based unit: \(unit.pageNumber)\(unit.isTruncated ? "; decoder text truncated" : "").",
                    "Excerpt: \(safe(unit.text, limit: 512))"]
            }
            if analysis.textPages.count > 3 { lines.append("\(analysis.textPages.count - 3) further decoded text units omitted from this report; see the validated decoder result.") }
        }
        if !analysis.warnings.isEmpty { lines += ["", "Decoder warnings: " + analysis.warnings.map { safe($0, limit: 512) }.joined(separator: "; ")] }
        return lines + [""]
    }

    private static func timestamp(_ value: UDFTimestamp) -> String {
        "raw hex \(safe(value.rawHex, limit: 64)); absolute source offset \(value.sourceOffset); type \(value.type); timezone minutes \(value.timezoneMinutes.map(String.init) ?? "unknown"); UTC date \(value.utcDate.map(utc) ?? "unknown"); microsecond \(value.microsecond)"
    }

    private static func utc(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    private static func flags(_ value: UInt8) -> String { String(format: "0x%02X", value) }
    private static func deleted(_ value: UInt8) -> String { value & 0x04 != 0 ? "set" : "clear" }

    private static func list(_ values: [String], limit: Int, count: Int, redactHostPaths: Bool = true) -> String {
        guard !values.isEmpty else { return "none recorded" }
        let rendered = values.prefix(count).map { safe($0, limit: limit, redactHostPaths: redactHostPaths) }.joined(separator: "; ")
        return rendered + (values.count > count ? "; \(values.count - count) additional values omitted (see saved receipt)" : "")
    }

    /// Recorded logical namespace paths stay evidence paths even when a name
    /// resembles a host directory. Arbitrary decoder/diagnostic values redact
    /// host paths before excerpting. Every value remains inert Markdown text.
    private static func safe(_ value: String, limit: Int, redactHostPaths: Bool = true) -> String {
        let hostPaths = #"(?:file://[^\s<>\"']+|/(?:Users|private|var|tmp|Volumes|Applications|Library|System|opt|usr)/[^\s<>\"']+|[A-Za-z]:[\\/][^\s<>\"']+)"#
        let redacted = redactHostPaths
            ? value.replacingOccurrences(of: hostPaths, with: "[host path redacted]", options: .regularExpression)
            : value
        var text = String(decoding: Array(redacted.utf8.prefix(limit)), as: UTF8.self)
        if redacted.utf8.count > limit { text += " [report excerpt truncated]" }
        let entities: [Character: String] = ["&": "&amp;", "<": "&lt;", ">": "&gt;", "|": "&#124;",
            "[": "&#91;", "]": "&#93;", "(": "&#40;", ")": "&#41;", "`": "&#96;",
            "\\": "&#92;", "!": "&#33;", "*": "&#42;", "_": "&#95;", "#": "&#35;",
            "{": "&#123;", "}": "&#125;", "\"": "&quot;", "'": "&#39;"]
        return text.map { character in
            if let entity = entities[character] { return entity }
            if character == "\n" || character == "\r" { return " ↵ " }
            if character.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) { return " " }
            return String(character)
        }.joined()
    }

    private struct BoundedReport {
        private var lines: [String] = []
        private var byteCount = 0
        private var rejectedSections = 0

        @discardableResult
        mutating func append(_ section: [String], reserve: Int = 4_096) -> Bool {
            let count = section.reduce(0) { $0 + $1.utf8.count + 1 }
            guard byteCount + count <= RecoveryReportBuilder.maximumReportBytes - reserve else {
                rejectedSections += 1; return false
            }
            lines += section; byteCount += count; return true
        }

        func finish() -> String {
            let suffix = "\nReport bound: \(RecoveryReportBuilder.maximumReportBytes) bytes. Sections or rows omitted by this bound: \(rejectedSections). Field-level excerpt limits are marked independently.\n"
            return lines.joined(separator: "\n") + "\n" + suffix
        }
    }
}
