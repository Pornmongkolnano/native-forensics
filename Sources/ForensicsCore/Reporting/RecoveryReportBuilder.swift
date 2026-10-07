import CryptoKit
import Darwin
import Foundation

@_silgen_name("flock")
private func reportFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

/// Reports contain receipts, decoder observations and explicit manual review.
/// They never embed thumbnails, image payloads or the host's source paths.
public enum RecoveryReportBuilder {
    public static let maximumReportBytes = 16 * 1_048_576

    public static func renderMarkdown(result: CarvingResult,
        analyses: [UUID: DocumentAnalysis], annotations: [UUID: RecoveryAnnotation] = [:]) -> String {
        do { try result.validate() }
        catch { return "# Recovery report unavailable\n\nThe recovery receipt failed validation. No findings were rendered.\n" }
        var acceptedAnalyses: [UUID: DocumentAnalysis] = [:]
        var acceptedAnnotations: [UUID: RecoveryAnnotation] = [:]
        var invalidAnalyses = 0, invalidAnnotations = 0
        let artifacts = Dictionary(uniqueKeysWithValues: result.artifacts.map { ($0.id, $0) })
        for (id, analysis) in analyses {
            do {
                guard let artifact = artifacts[id] else { throw RecoveryError.scopeMismatch }
                try validate(analysis, artifact: artifact)
                acceptedAnalyses[id] = analysis
            } catch { invalidAnalyses += 1 }
        }
        for (id, annotation) in annotations {
            do {
                guard artifacts[id] != nil, id == annotation.artifactID else { throw RecoveryError.scopeMismatch }
                try annotation.validate(); acceptedAnnotations[id] = annotation
            } catch { invalidAnnotations += 1 }
        }
        return render(result: result, analyses: acceptedAnalyses, annotations: acceptedAnnotations,
                      invalidAnalyses: invalidAnalyses, invalidAnnotations: invalidAnnotations)
    }

    /// The case is required so every original evidence path and the entire case
    /// storage namespace can be excluded from the export destination.
    @discardableResult
    public static func exportMarkdown(result: CarvingResult, analyses: [UUID: DocumentAnalysis],
        annotations: [UUID: RecoveryAnnotation] = [:], in caseURL: URL, to outputURL: URL) throws -> URL {
        try strictValidation(result: result, analyses: analyses, annotations: annotations)
        try Task.checkCancellation()
        guard caseURL.isFileURL, outputURL.isFileURL, outputURL.host == nil || outputURL.host == ""
            || outputURL.host == "localhost", !outputURL.path.utf8.contains(0) else {
            throw RecoveryError.storageChanged
        }
        let bundle = caseURL.standardizedFileURL, destination = outputURL.standardizedFileURL
        let root = try EvidenceViewFiles.openDirectory(bundle)
        defer { Darwin.close(root) }
        let lock = try FileAccess.openReadOnly(".case.lock", in: root)
        defer { Darwin.close(lock) }
        let lockIdentity = try FileAccess.identity(of: lock)
        var lockInfo = stat()
        guard Darwin.fstat(lock, &lockInfo) == 0, lockInfo.st_nlink == 1 else { throw RecoveryError.storageChanged }
        while reportFlock(lock, LOCK_SH | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            guard errno == EWOULDBLOCK else { throw FileAccess.posixError("Cannot lock recovery report") }
            try Task.checkCancellation(); usleep(10_000)
        }
        defer { _ = reportFlock(lock, LOCK_UN) }
        let forensicCase = try CaseStore.open(at: bundle)
        guard forensicCase.manifest.id == result.caseID,
              let evidence = forensicCase.manifest.evidence.first(where: { $0.id == result.sourceEvidenceID }),
              evidence.container == .raw, evidence.sha256 == result.sourceSHA256,
              evidence.byteCount == result.sourceByteCount, evidence.hashScope == result.sourceHashScope,
              !FileAccess.isInside(destination, directory: bundle),
              !forensicCase.manifest.evidence.contains(where: {
                  URL(fileURLWithPath: $0.sourcePath).standardizedFileURL.path == destination.path
              }),
              try RecoveryResultStore.load(jobID: result.jobID, evidenceID: result.sourceEvidenceID,
                                           in: bundle) == result else { throw RecoveryError.scopeMismatch }
        let manifestIdentity = try FileAccess.identity(at: "manifest.json", in: root)
        // A cached decoder receipt is not permission to report a tampered
        // historical payload. Verify every recovered file's full bytes once,
        // then pin its identity until this export's publication boundary.
        var payloadIdentities: [(URL, SourceIdentity)] = []
        for artifact in result.artifacts {
            try Task.checkCancellation()
            let payload = try RecoveryResultStore.artifactURL(artifact: artifact, result: result, in: bundle)
            payloadIdentities.append((payload, try FileAccess.identity(at: payload)))
        }
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
            guard try RecoveryResultStore.load(jobID: result.jobID, evidenceID: result.sourceEvidenceID,
                in: bundle) == result else { throw RecoveryError.scopeMismatch }
            for (payload, identity) in payloadIdentities {
                guard (try? FileAccess.identity(at: payload)) == identity else { throw RecoveryError.artifactChanged }
            }
        }
        try validate()
        let report = render(result: result, analyses: analyses, annotations: annotations,
                            invalidAnalyses: 0, invalidAnnotations: 0)
        let bytes = Data(report.utf8)
        guard bytes.count <= maximumReportBytes else { throw RecoveryError.outputLimit }
        let staging = ".recovery-report-\(UUID().uuidString.lowercased()).tmp"
        let output = Darwin.openat(parent, staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard output >= 0 else { throw FileAccess.posixError("Cannot create recovery report") }
        defer {
            if EvidenceViewFiles.referenceMatches(staging, parent: parent, descriptor: output) {
                _ = Darwin.unlinkat(parent, staging, 0)
            }
            Darwin.close(output)
        }
        try bytes.withUnsafeBytes { buffer in
            var written = 0
            while written < buffer.count {
                try Task.checkCancellation()
                let count = Darwin.write(output, buffer.baseAddress?.advanced(by: written),
                                         min(65_536, buffer.count - written))
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FileAccess.posixError("Cannot write recovery report") }
                written += count
            }
        }
        guard Darwin.fsync(output) == 0 else { throw FileAccess.posixError("Cannot flush recovery report") }
        try Task.checkCancellation(); try validate()
        guard EvidenceViewFiles.referenceMatches(staging, parent: parent, descriptor: output) else {
            throw RecoveryError.storageChanged
        }
        try Task.checkCancellation()
        guard Darwin.renameatx_np(parent, staging, parent, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw RecoveryError.destinationExists }
            throw FileAccess.posixError("Cannot publish recovery report")
        }
        guard Darwin.fsync(parent) == 0 else { throw FileAccess.posixError("Cannot flush report directory") }
        // The synchronized rename is the commit boundary. Cancellation after
        // publication must not hide a successfully saved report from the UI.
        return destination
    }

    private static func strictValidation(result: CarvingResult, analyses: [UUID: DocumentAnalysis],
                                          annotations: [UUID: RecoveryAnnotation]) throws {
        try result.validate()
        let artifacts = Dictionary(uniqueKeysWithValues: result.artifacts.map { ($0.id, $0) })
        for (id, analysis) in analyses {
            guard let artifact = artifacts[id] else { throw RecoveryError.scopeMismatch }
            try validate(analysis, artifact: artifact)
        }
        for (id, annotation) in annotations {
            guard artifacts[id] != nil, annotation.artifactID == id else { throw RecoveryError.scopeMismatch }
            try annotation.validate()
        }
    }

    private static func validate(_ analysis: DocumentAnalysis, artifact: CarvedArtifact) throws {
        try DocumentAnalysisClient.validate(analysis, for: DocumentInput(fileURL: URL(fileURLWithPath: "/"),
            expectedSHA256: artifact.sha256, expectedByteCount: artifact.byteCount))
    }

    private static func render(result: CarvingResult, analyses: [UUID: DocumentAnalysis],
                               annotations: [UUID: RecoveryAnnotation], invalidAnalyses: Int,
                               invalidAnnotations: Int) -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let receiptDigest = (try? encoder.encode(result)).map {
            SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined()
        } ?? "unavailable"
        var lines = ["# Signature recovery report", "",
            "- Case ID: \(result.caseID.uuidString.lowercased())",
            "- Evidence ID: \(result.sourceEvidenceID.uuidString.lowercased())",
            "- Recovery job ID: \(result.jobID.uuidString.lowercased())",
            "- Recovery receipt SHA-256: \(receiptDigest)",
            "- Selected source SHA-256: \(result.sourceSHA256)",
            "- Source size: \(result.sourceByteCount) bytes",
            "- Source hash scope: \(result.sourceHashScope)",
            "- Source offset scope: \(result.sourceOffsetScope)",
            "- Requested scan scope: \(result.options.scanScope); status: \(result.status.rawValue)",
            "- Recovery bounds: \(result.options.maximumFiles) files; \(result.options.maximumOutputBytes) output bytes; \(result.options.maximumArtifactBytes) bytes per artifact",
            "- Recovery tool: PhotoRec \(safe(result.photoRecVersion, limit: 128)); executable SHA-256: \(result.executableSHA256)",
            "- Recovered candidates: \(result.artifacts.count)", "",
            "Signature candidates are not filesystem entries. Original names, allocation state and deletion status are unknown. A source-byte mapping verifies bytes, not decoder accessibility or deletion. Format hints come from recovery filename extensions; decoder MIME observations are listed separately.", "",
            "Source SHA-256 and source-byte verification are recorded recovery-time provenance; the selected source is not reopened by report export. Report export independently verifies every stored recovered file against its size and hash receipt before publication.", "",
            "Examiner assessments and notes are manual observations, not automatically verified findings. Source and host paths are omitted or redacted. Image payloads and thumbnails are excluded.", "",
            "PDF/text/Office/ZIP search scope is the locally decoded text units only. PDF pages, slides, worksheets, document bodies and archive member names retain their own references; DOCX text does not imply a rendered page layout. ZIP text members are bounded previews without recursive extraction, and their decoder receipt remains bound to the parent archive. No OCR or image-content search is implied; missing, empty, binary, skipped or truncated units make text coverage partial. EXIF values remain raw file metadata; an unzoned date is not converted to an epoch or assigned a host time zone.", ""]
        if result.status == .partial {
            lines += ["Recovery status is partial: this inventory is the observed candidate subset, not a proof that the requested scan scope was completely processed.", ""]
        }
        if invalidAnalyses > 0 || invalidAnnotations > 0 {
            lines += ["Validation diagnostics: \(invalidAnalyses) mismatched/invalid decoder results and \(invalidAnnotations) out-of-scope/invalid annotations were excluded. Export requires all supplied records to validate.", ""]
        }
        if !result.warnings.isEmpty {
            lines += ["Recovery warnings: " + result.warnings.map { safe($0, limit: 512) }.joined(separator: "; "), ""]
        }
        lines += ["## Candidate inventory", "",
            "| Artifact ID | Recovery filename | Bytes | Recovered SHA-256 | Format hint | Decoder MIME | Decoder status | Source-byte mapping | Deletion | Examiner assessment |",
            "| --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- |"]
        for artifact in result.artifacts {
            let analysis = analyses[artifact.id], annotation = annotations[artifact.id]
            lines.append("| \(artifact.id.uuidString.lowercased()) | \(safe(artifact.filename, limit: 256)) | \(artifact.byteCount) | \(artifact.sha256) | \(safe(artifact.formatHint, limit: 64)) | \(analysis.map { safe($0.mimeType, limit: 128) } ?? "unknown (not analyzed)") | \(analysis?.status.rawValue ?? "unknown (not analyzed)") | \(artifact.validationStatus.rawValue) | unknown | \(annotation?.assessment.rawValue ?? "notReviewed") |")
        }
        lines += ["", "## Candidate observations", ""]
        var usedBytes = lines.reduce(0) { $0 + $1.utf8.count + 1 }
        var omitted = 0
        for artifact in result.artifacts {
            let section = observations(artifact: artifact, analysis: analyses[artifact.id],
                                       annotation: annotations[artifact.id])
            let count = section.reduce(0) { $0 + $1.utf8.count + 1 }
            if usedBytes + count > maximumReportBytes - 512 { omitted += 1; continue }
            lines += section; usedBytes += count
        }
        if omitted > 0 {
            lines += ["Detailed observations omitted for \(omitted) candidates to keep this report below \(maximumReportBytes) bytes. The candidate inventory above remains complete. Open the case for full receipts and annotations.", ""]
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private static func observations(artifact: CarvedArtifact, analysis: DocumentAnalysis?,
                                      annotation: RecoveryAnnotation?) -> [String] {
        var lines = ["### Artifact \(artifact.id.uuidString.lowercased())", "",
            "Recovery filename: \(safe(artifact.filename, limit: 1_024)); \(artifact.byteCount) recovered-file bytes. Deletion status: unknown.", "",
            "Reported byte runs (output offset → source offset + length): \(runs(artifact.reportedByteRuns))",
            "Verified/clipped byte runs (output offset → source offset + length): \(runs(artifact.verifiedByteRuns))", ""]
        if !artifact.warnings.isEmpty {
            lines += ["Byte/recovery warnings: " + artifact.warnings.map { safe($0, limit: 512) }.joined(separator: "; "), ""]
        }
        if let analysis {
            lines += ["Decoder observation: \(analysis.status.rawValue); MIME \(safe(analysis.mimeType, limit: 128)); kind \(analysis.contentKind.rawValue). Decoder receipt matches the recovered-file SHA-256 and size.", ""]
            if let code = analysis.failureCode { lines += ["Decoder failure code: \(safe(code, limit: 128))", ""] }
            if let format = analysis.officeFormat {
                lines += ["Office format: \(format.rawValue); structural validation: \(analysis.structuralValidation?.rawValue ?? "unknown"). Structural recognition alone does not establish readable document content.", ""]
            }
            if let width = analysis.pixelWidth, let height = analysis.pixelHeight {
                lines += ["Image dimensions: \(width) × \(height) pixels.", ""]
            }
            if !analysis.rawMetadata.isEmpty {
                lines += ["Raw file metadata (dates remain raw; absent offsets mean zone unknown):", ""]
                for metadata in analysis.rawMetadata.prefix(16) {
                    lines.append("- \(safe(metadata.name, limit: 128)): \(safe(metadata.value, limit: 512))")
                }
                if analysis.rawMetadata.count > 16 { lines.append("Additional raw metadata items omitted from this report: \(analysis.rawMetadata.count - 16).") }
                lines.append("")
            }
            if analysis.contentKind == .pdf || analysis.contentKind == .text || analysis.contentKind == .office || analysis.contentKind == .archive {
                let scope = analysis.textIsComplete ? "complete decoded-text coverage" : "partial or unavailable decoded-text coverage"
                let noun = analysis.contentKind == .pdf ? "pages" : "text units"
                let total = (analysis.contentKind == .office || analysis.contentKind == .archive) ? analysis.contentUnitCount : analysis.pageCount
                lines += ["Text-search scope: \(scope); decoded \(noun) \(analysis.textPages.count)/\(total.map(String.init) ?? "unknown"). No OCR. Report excerpts are bounded and are not a complete text export.", ""]
                for page in analysis.textPages.prefix(3) {
                    let reference = page.referenceLabel.map { safe($0, limit: 256) }
                        ?? (analysis.contentKind == .pdf ? "Page \(page.pageNumber)" : "Text unit \(page.pageNumber)")
                    lines += ["\(reference)\(page.isTruncated ? " (decoder text truncated)" : ""): \(safe(page.text, limit: 512))", ""]
                }
                if analysis.textPages.count > 3 { lines += ["Further decoded text units are available in the case: \(analysis.textPages.count - 3).", ""] }
            }
            if !analysis.warnings.isEmpty {
                lines += ["Decoder warnings: " + analysis.warnings.map { safe($0, limit: 512) }.joined(separator: "; "), ""]
            }
        } else {
            lines += ["Decoder status: unknown (not analyzed). Accessibility, MIME, EXIF and document text were not established.", ""]
        }
        lines += ["Examiner assessment (manual): \(annotation?.assessment.rawValue ?? "notReviewed")",
                  "Examiner note (manual): \(safe(annotation?.note ?? "", limit: RecoveryAnnotation.maximumNoteBytes))", ""]
        return lines
    }

    private static func runs(_ runs: [RecoveryByteRun]) -> String {
        guard !runs.isEmpty else { return "none" }
        let preview = runs.prefix(32).map { "\($0.outputOffset) → \($0.sourceOffset) + \($0.length) bytes" }.joined(separator: "; ")
        return preview + (runs.count > 32 ? "; \(runs.count - 32) additional runs omitted (see receipt)" : "")
    }

    private static func safe(_ value: String, limit: Int) -> String {
        let hostPaths = #"/(?:Users|private|var|tmp|Volumes|Applications|Library|System|opt|usr)/[^\s<>\"']+"#
        let redacted = value.replacingOccurrences(of: hostPaths, with: "[host path redacted]", options: .regularExpression)
        var text = String(decoding: Array(redacted.utf8.prefix(limit)), as: UTF8.self)
        if redacted.utf8.count > limit { text += " [report excerpt truncated]" }
        // Escape all link/HTML/table delimiters. Source text is never interpreted
        // as a Markdown link, HTML element, image or injected inventory row.
        let entities: [Character: String] = ["&": "&amp;", "<": "&lt;", ">": "&gt;", "|": "&#124;",
            "[": "&#91;", "]": "&#93;", "(": "&#40;", ")": "&#41;", "`": "&#96;",
            "\\": "&#92;", "!": "&#33;", "*": "&#42;", "_": "&#95;", "#": "&#35;",
            "{": "&#123;", "}": "&#125;"]
        return text.map { character in
            if let entity = entities[character] { return entity }
            if character == "\n" || character == "\r" { return " ↵ " }
            if character.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) { return " " }
            return String(character)
        }.joined()
    }
}
