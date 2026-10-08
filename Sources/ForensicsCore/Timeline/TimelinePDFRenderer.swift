import CoreGraphics
import CoreText
import Foundation

/// Native static-text PDF output. This does not inspect source bytes or invoke
/// PDFKit, a web view, a document decoder, or an external rendering process.
public enum TimelinePDFRenderer {
    public static let version = "timeline-coretext-pdf.v1"
    public static func render(_ report: TimelineReport) throws -> Data {
        try render(report, byteLimit: TimelineLimits.maximumReportBytes, pageLimit: maximumPages)
    }

    // A second bound limits work even when many repeated lines compress well.
    // Exceeding either bound rejects the whole PDF; it never drops later text.
    static let maximumPages = 10_000

    /// Reduced limits support inexpensive regression tests of fail-closed output.
    static func render(_ report: TimelineReport, byteLimit: Int, pageLimit: Int) throws -> Data {
        try TimelineReportExporter.validate(report)
        try Task.checkCancellation()
        guard (1...TimelineLimits.maximumReportBytes).contains(byteLimit), (1...maximumPages).contains(pageLimit) else {
            throw TimelineError.invalidInput("Invalid timeline PDF output limits.")
        }
        let output = TimelinePDFOutput(byteLimit: byteLimit)
        var callbacks = CGDataConsumerCallbacks(putBytes: { info, buffer, count in
            guard let info else { return 0 }
            return Unmanaged<TimelinePDFOutput>.fromOpaque(info).takeUnretainedValue().append(buffer, count: count)
        }, releaseConsumer: nil)
        guard let consumer = CGDataConsumer(info: Unmanaged.passUnretained(output).toOpaque(), cbks: &callbacks) else {
            throw TimelineError.publication("Could not create the timeline PDF output stream.")
        }
        var box = CGRect(x: 0, y: 0, width: 612, height: 792)
        let metadata = [kCGPDFContextTitle: "NativeForensics timeline", kCGPDFContextCreator: "NativeForensics \(version)"] as CFDictionary
        guard let context = CGContext(consumer: consumer, mediaBox: &box, metadata) else {
            try output.check()
            throw TimelineError.publication("Could not create the timeline PDF context.")
        }
        let writer = TimelinePDFPages(context: context, output: output, pageLimit: pageLimit, box: box)
        defer { writer.close() }
        try writer.heading("NativeForensics timeline", level: 1)
        try writer.field("Report schema version", String(report.schemaVersion))
        try writer.field("Report parser version", report.parserVersion)
        try writer.field("PDF renderer version", version)
        try writer.field("PDF output bounds", "\(byteLimit) bytes; \(pageLimit) pages; complete-report failure on overflow")
        try writer.field("Event count", String(report.events.count))
        try writer.paragraph("This report describes recorded snapshots and parser observations. Hashes identify recorded bytes; they do not establish the truth of an observation. Evidence source bytes were not reread by this renderer.")
        try writer.paragraph("Rendering convention: line-feed characters form line breaks. Tabs, carriage returns and other C0/DEL control characters are printed as literal escapes so invisible controls are not lost.")

        try writer.heading("Provenance and coverage")
        let binding = report.binding
        try writer.field("Case ID", binding.caseID.uuidString)
        try writer.field("Evidence ID", binding.evidenceID.uuidString)
        try writer.field("Recorded snapshot SHA-256", binding.snapshotSHA256)
        let date = ISO8601DateFormatter()
        date.timeZone = TimeZone(secondsFromGMT: 0)
        date.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        try writer.field("Snapshot saved at (UTC)", date.string(from: binding.snapshotSavedAt))
        try writer.field("Snapshot saved at (Unix seconds)", String(binding.snapshotSavedAt.timeIntervalSince1970))
        try writer.field("Engine version", binding.engineVersion)
        try writer.field("Engine selected timezone", binding.engineTimezone)
        try writer.field("Listing status", binding.listingStatus.rawValue)
        try writer.field("Historical snapshot", String(binding.historical))
        if let scopes = binding.hashScopes {
            for key in scopes.keys.sorted() { try writer.field("Hash scope \(key)", scopes[key]!) }
        } else { try writer.field("Encoded hash scopes", "Unavailable (not retained in this historical binding)") }
        try writer.field("Coverage", report.coverage)
        try writer.paragraph("Container hashes describe selected file bytes in recorded input order. Logical-image hashes describe logical/decompressed image bytes separately.")
        for (ordinal, hash) in binding.orderedContainerSHA256.enumerated() {
            try writer.field("Container input \(ordinal) SHA-256", hash)
        }
        try writer.field("Logical-image bytes SHA-256", binding.logicalImageSHA256 ?? "Unavailable (not recorded)")
        if let engine = binding.engineProvenance {
            try writer.heading("Readable engine provenance")
            try writer.field("Engine schema version", String(engine.schemaVersion))
            try writer.field("Engine patch digest", engine.patchDigest)
            try writer.field("Requested image type", engine.options.imageType)
            try writer.field("Requested sector size", String(engine.options.sectorSize))
            try writer.field("Requested timezone", engine.options.timezone)
            try writer.field("Requested maximum files", String(engine.options.maxFiles))
            try writer.field("Requested logical-image hashing", String(engine.options.hashLogicalImage))
            try writer.field("Recorded image type", engine.image.imageType)
            try writer.field("Recorded logical image size", String(engine.image.logicalSize))
            try writer.field("Recorded image sector size", String(engine.image.sectorSize))
            try writer.field("Recorded image hash scope", engine.image.hashScope)
            try writer.field("Recorded image logical SHA-256", engine.image.logicalSha256 ?? "Unavailable (not recorded)")
            for input in engine.orderedInputs {
                try writer.field("Ordered engine input \(input.ordinal)", "byte count: \(input.byteCount.map(String.init) ?? "unavailable"); hash scope: \(input.hashScope); SHA-256: \(input.sha256)")
            }
            try writer.field("Recorded volume count", String(engine.volumes.count))
            for (ordinal, volume) in engine.volumes.enumerated() {
                try writer.field("Volume \(ordinal) ID", volume.id)
                try writer.field("Volume \(ordinal) geometry", "offset bytes: \(volume.offsetBytes); filesystem: \(volume.filesystem); block size: \(volume.blockSize); block count: \(volume.blockCount)")
            }
        } else {
            try writer.field("Readable engine provenance", "Unavailable (not recorded in this historical report)")
        }

        try writer.heading("Artifact receipts")
        if report.artifactReceipts.isEmpty { try writer.paragraph("No artifact receipts were recorded.") }
        for (index, file) in report.artifactReceipts.enumerated() {
            try writer.heading("Artifact \(index + 1): \(file.role)", level: 3)
            try writer.field("Artifact role", file.role)
            try writer.field("Artifact evidence path", file.evidencePath)
            try writer.field("Artifact file ID", file.fileID)
            try writer.field("Extracted byte count", String(file.byteCount))
            try writer.field("Extracted bytes SHA-256", file.sha256)
            try writer.field("Artifact encoded hash scope", file.hashScope ?? "Unavailable (not retained in this historical receipt)")
        }
        try writer.heading("Parser receipts")
        if let receipts = report.parserReceipts {
            if receipts.isEmpty { try writer.paragraph("No parser receipts were recorded.") }
            for (index, receipt) in receipts.enumerated() {
                try writer.heading("Parser receipt \(index + 1)", level: 3)
                try writer.field("Parser", receipt.parser)
                try writer.field("Parser version", receipt.version)
                try writer.field("Parser source SHA-256", receipt.sourceSHA256 ?? "Unavailable (not recorded)")
                try writer.field("Parser source hash scope", receipt.sourceHashScope ?? "Unavailable (not recorded)")
                try writer.field("Parser derived text SHA-256", receipt.derivedTextSHA256 ?? "Unavailable (not recorded)")
                try writer.field("Parser derived text hash scope", receipt.derivedTextHashScope ?? "Unavailable (not recorded)")
                try writer.field("Parser unit count", receipt.unitCount.map(String.init) ?? "Unavailable (not recorded)")
                try writer.field("Parser line count", receipt.lineCount.map(String.init) ?? "Unavailable (not recorded)")
                try writer.field("Parser event count", String(receipt.eventCount))
                if receipt.parameters.isEmpty { try writer.field("Parser parameters", "None") }
                for key in receipt.parameters.keys.sorted() {
                    try writer.field("Parser parameter \(key)", receipt.parameters[key]!)
                }
            }
        } else {
            try writer.paragraph("Parser receipts are unavailable (not recorded in this historical report).")
        }
        try writer.heading("Limits and assumptions")
        if report.warnings.isEmpty { try writer.paragraph("No additional warnings were recorded.") }
        for (index, warning) in report.warnings.enumerated() { try writer.field("Warning \(index + 1)", warning) }

        try writer.heading("Deterministic parser observations")
        try writer.paragraph("UTC epoch seconds and nanoseconds are normalized values. Raw timestamp, precision, zone assumptions and alternative epochs remain explicit. Unresolved timestamps have no selected UTC instant. A deleted entry does not establish its deletion time. Events are printed in the recorded report order.")
        if report.events.isEmpty { try writer.paragraph("No events were recorded.") }
        for (index, event) in report.events.enumerated() {
            try Task.checkCancellation()
            try writer.heading("Event \(index + 1) of \(report.events.count)", level: 3)
            try writer.field("Event ID", event.id)
            try writer.field("Kind", event.kind.rawValue)
            try writer.field("Entry state", event.isDeleted ? "deleted entry; deletion time unknown" : "allocated / recorded")
            try writer.field("Evidence path", event.evidencePath)
            try writer.field("File ID", event.fileID)
            try writer.field("Artifact record ID", event.recordID)
            try writer.field("Event parser", event.parser)
            try writer.field("Event artifact SHA-256", event.artifactSHA256 ?? "Unavailable (no artifact hash recorded)")
            try writer.field("Raw timestamp", event.timestamp.rawValue)
            try writer.field("UTC epoch seconds", event.timestamp.epochSeconds.map(String.init) ?? "unresolved")
            try writer.field("Nanoseconds", String(event.timestamp.nanoseconds))
            try writer.field("Timestamp precision", event.timestamp.precision)
            try writer.field("Timezone / epoch assumption", event.timestamp.timezoneAssumption ?? "none")
            try writer.field("Timestamp interpretation", event.timestamp.interpretation)
            try writer.field("Alternative UTC epoch seconds", event.timestamp.alternativeEpochSeconds.isEmpty ? "none" : event.timestamp.alternativeEpochSeconds.map(String.init).joined(separator: ", "))
            if let native = event.filesystemTimestamp {
                try writer.field("Native filesystem raw date", String(native.rawDate))
                try writer.field("Native filesystem raw time", String(native.rawTime))
                try writer.field("Native filesystem raw increment", native.rawIncrement.map(String.init) ?? "Unavailable (not recorded)")
                try writer.field("Native filesystem raw UTC offset", native.rawUTCOffset.map(String.init) ?? "Unavailable (not recorded)")
                try writer.field("Native filesystem civil value", native.civil ?? "Unavailable (not recorded)")
                try writer.field("Native filesystem timestamp status", native.status.rawValue)
                try writer.field("Native filesystem timezone", native.timezone ?? "Unavailable (not recorded)")
                try writer.field("Native filesystem UTC offset minutes", native.utcOffsetMinutes.map(String.init) ?? "Unavailable (not recorded)")
                try writer.field("Native filesystem candidate UTC epochs", native.candidateEpochs.isEmpty ? "none" : native.candidateEpochs.map(String.init).joined(separator: ", "))
                try writer.field("Native filesystem precision nanoseconds", String(native.precisionNanoseconds))
            } else { try writer.field("Native filesystem timestamp", "Unavailable (not recorded / not applicable)") }
            if let source = event.sourceReference {
                try writer.field("Source derived text SHA-256", source.derivedTextSHA256)
                try writer.field("Source text unit", "\(source.unit) (\(source.unitKind))")
                try writer.field("Source text line", String(source.line))
                try writer.field("Source UTF-8 byte offset", String(source.utf8Offset))
                try writer.field("Source UTF-8 byte length", String(source.utf8Length))
            } else { try writer.field("Text source pointer", "Unavailable (not recorded / not applicable)") }
            try writer.field("Observation title", event.title)
            try writer.field("Observation detail", event.detail)
        }
        try writer.heading("Examiner notes")
        try writer.paragraph(report.examinerNotes.isEmpty ? "No examiner notes were included." : report.examinerNotes)
        try writer.heading("AI interpretation (unverified)")
        try writer.paragraph("This section is separate from deterministic observations and examiner notes. It is not a verified parser finding.")
        try writer.paragraph(report.aiInterpretation ?? "No AI interpretation was included.")
        writer.close()
        try Task.checkCancellation()
        try output.check()
        guard !output.data.isEmpty else { throw TimelineError.publication("The timeline PDF output is empty.") }
        return output.data
    }
}

/// CGDataConsumer writes are checked before allocation, including the final PDF
/// trailer written by closePDF. A failed stream is never returned to callers.
private final class TimelinePDFOutput {
    let byteLimit: Int
    private(set) var data = Data()
    private var exceeded = false
    init(byteLimit: Int) { self.byteLimit = byteLimit }
    func append(_ buffer: UnsafeRawPointer, count: Int) -> Int {
        guard !exceeded, count >= 0, count <= byteLimit - data.count else { exceeded = true; return 0 }
        data.append(buffer.assumingMemoryBound(to: UInt8.self), count: count)
        return count
    }
    func check() throws {
        if exceeded { throw TimelineError.limitExceeded("Timeline PDF exceeds its 64 MiB output budget.") }
    }
}

private final class TimelinePDFPages {
    let context: CGContext
    let output: TimelinePDFOutput
    let pageLimit: Int
    let box: CGRect
    let margin: CGFloat = 36
    let bodyTop: CGFloat = 738
    let bodyBottom: CGFloat = 48
    private var y: CGFloat = 738
    private var pages = 0
    private var pageOpen = false
    private var closed = false
    init(context: CGContext, output: TimelinePDFOutput, pageLimit: Int, box: CGRect) {
        self.context = context; self.output = output; self.pageLimit = pageLimit; self.box = box
    }
    func close() {
        guard !closed else { return }; closed = true
        if pageOpen { context.endPDFPage(); pageOpen = false }
        context.closePDF()
    }
    func heading(_ text: String, level: Int = 2) throws {
        // Reserve space for a heading and at least two ordinary body lines.
        let size: CGFloat = level == 1 ? 18 : (level == 2 ? 12 : 10)
        try ensureSpace(size * 1.5 + 28)
        y -= level == 1 ? 0 : 8
        try paragraph(text, fontSize: size, bold: true, spacing: 4)
    }
    func field(_ label: String, _ value: String) throws {
        try paragraph("\(label): \(value.isEmpty ? "(empty)" : value)")
    }
    func paragraph(_ text: String, fontSize: CGFloat = 9, bold: Bool = false, spacing: CGFloat = 3) throws {
        try Task.checkCancellation()
        try output.check()
        let font = CTFontCreateWithName((bold ? "Helvetica-Bold" : "Helvetica") as CFString, fontSize, nil)
        let attributes: [NSAttributedString.Key: Any] = [
            NSAttributedString.Key(kCTFontAttributeName as String): font,
            NSAttributedString.Key(kCTForegroundColorAttributeName as String): CGColor(gray: 0.08, alpha: 1)
        ]
        let value = NSAttributedString(string: visibleControls(text), attributes: attributes)
        let typesetter = CTTypesetterCreateWithAttributedString(value)
        let width = box.width - margin * 2
        var offset = 0
        // CoreText consumes UTF-16 ranges, not Character or UTF-8 counts. Always
        // advance by the range actually drawn, including newlines/whitespace.
        while offset < value.length {
            try Task.checkCancellation()
            var count = CTTypesetterSuggestLineBreak(typesetter, offset, Double(width))
            if count == 0 { count = CTTypesetterSuggestClusterBreak(typesetter, offset, Double(width)) }
            guard count > 0, count <= value.length - offset else {
                throw TimelineError.limitExceeded("Timeline PDF contains a text cluster that cannot fit a page without clipping.")
            }
            let line = CTTypesetterCreateLine(typesetter, CFRange(location: offset, length: count))
            var ascent: CGFloat = 0, descent: CGFloat = 0, leading: CGFloat = 0
            let advance = CTLineGetTypographicBounds(line, &ascent, &descent, &leading)
            let glyphs = CTLineGetBoundsWithOptions(line, .useGlyphPathBounds)
            let leftInset = max(0, -glyphs.minX)
            // CoreText can consume thousands of trailing spaces in one line.
            // Those do not paint outside the page, unlike an oversized glyph.
            let visibleAdvance = max(0, advance - CTLineGetTrailingWhitespaceWidth(line))
            guard max(visibleAdvance, glyphs.maxX) + leftInset <= width + 0.5 else {
                throw TimelineError.limitExceeded("Timeline PDF contains a text cluster wider than a page.")
            }
            let top = max(ascent, glyphs.maxY)
            let bottom = max(descent, -glyphs.minY)
            let height = max(fontSize * 1.3, top + bottom + max(0, leading) + 1)
            guard height.isFinite, height <= bodyTop - bodyBottom else {
                throw TimelineError.limitExceeded("Timeline PDF contains a text cluster taller than a page.")
            }
            try ensureSpace(height)
            context.textMatrix = .identity
            context.textPosition = CGPoint(x: margin + leftInset, y: y - top)
            CTLineDraw(line, context)
            offset += count
            y -= height
        }
        y -= spacing
    }
    private func visibleControls(_ text: String) -> String {
        var result = String()
        result.reserveCapacity(text.utf8.count)
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 9: result += "\\t"
            case 13: result += "\\r"
            case 0..<9, 11..<13, 14..<32, 127:
                result += String(format: "\\u%04X", scalar.value)
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result
    }
    private func ensureSpace(_ height: CGFloat) throws {
        try Task.checkCancellation()
        try output.check()
        guard !closed else { throw TimelineError.publication("The timeline PDF stream was already closed.") }
        if pageOpen, y - height >= bodyBottom { return }
        guard pages < pageLimit else { throw TimelineError.limitExceeded("Timeline PDF exceeds its \(pageLimit)-page pagination budget.") }
        if pageOpen { context.endPDFPage(); pageOpen = false; try output.check() }
        context.beginPDFPage(nil); pageOpen = true; pages += 1; y = bodyTop
        drawChrome("NativeForensics timeline", at: CGPoint(x: margin, y: 760), size: 8)
        drawChrome("Recorded evidence report - page \(pages)", at: CGPoint(x: margin, y: 28), size: 8)
        context.setStrokeColor(CGColor(gray: 0.75, alpha: 1))
        context.setLineWidth(0.5)
        context.move(to: CGPoint(x: margin, y: 751)); context.addLine(to: CGPoint(x: box.width - margin, y: 751)); context.strokePath()
    }
    private func drawChrome(_ text: String, at point: CGPoint, size: CGFloat) {
        let attributes: [NSAttributedString.Key: Any] = [
            NSAttributedString.Key(kCTFontAttributeName as String): CTFontCreateWithName("Helvetica" as CFString, size, nil),
            NSAttributedString.Key(kCTForegroundColorAttributeName as String): CGColor(gray: 0.35, alpha: 1)
        ]
        let line = CTLineCreateWithAttributedString(NSAttributedString(string: text, attributes: attributes))
        context.textMatrix = .identity; context.textPosition = point; CTLineDraw(line, context)
    }
}
