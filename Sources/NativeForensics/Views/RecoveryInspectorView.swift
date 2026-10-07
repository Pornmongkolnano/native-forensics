import AppKit
import ForensicsCore
import SwiftUI

struct RecoveryInspectorView: View {
    let workspace: WorkspaceStore
    @State private var pane: RecoveryInspectorPane = .properties

    private enum RecoveryInspectorPane: String, CaseIterable {
        case properties = "Properties"
        case preview = "Preview"
        case integrity = "Integrity"
    }

    private var store: RecoveryWorkspaceStore { workspace.recovery }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "doc.badge.arrow.up")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(store.selectedArtifact?.filename ?? "Recovery Inspector")
                            .font(.headline)
                            .lineLimit(2)
                            .truncationMode(.middle)
                        Text("Signature recovery candidate")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Picker("Recovery inspector information", selection: $pane) {
                    ForEach(RecoveryInspectorPane.allCases, id: \.self) { pane in
                        Text(pane.rawValue).tag(pane)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .accessibilityLabel("Recovery inspector information")
            }
            .padding(16)
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 16) {
                    if let artifact = store.selectedArtifact {
                        switch pane {
                        case .properties:
                            RecoveryCandidatePropertiesView(artifact: artifact, store: store)
                        case .preview:
                            RecoveryDocumentPreviewView(artifact: artifact, store: store)
                        case .integrity:
                            RecoveryCandidateIntegrityView(artifact: artifact, result: store.result, store: store)
                        }
                    } else {
                        Text("Select a recovered candidate to review its bytes, preview supported content and inspect its provenance.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onChange(of: store.result?.sourceEvidenceID) { _, _ in pane = .properties }
        .onChange(of: store.analysis?.sourceSHA256) { _, hash in
            if hash != nil { pane = .preview }
        }
    }
}

private struct RecoveryCandidatePropertiesView: View {
    let artifact: CarvedArtifact
    let store: RecoveryWorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            RecoveryInspectorField(label: "Recovered Filename", value: artifact.filename)
            RecoveryInspectorField(label: "Exact Size", value: "\(artifact.byteCount.formatted()) bytes")
            RecoveryInspectorField(label: "Format Hint", value: artifact.formatHint.isEmpty ? "Unknown" : artifact.formatHint.uppercased())
            Text("Hint scope: PhotoRec recovery filename extension. Successful decoding is checked separately in Preview.")
                .font(.caption)
                .foregroundStyle(.secondary)
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    RecoveryInspectorField(label: "Deletion State", value: "Unknown")
                    RecoveryInspectorField(label: "Original Name / Filesystem Path", value: "Not established by signature recovery")
                    RecoveryInspectorField(label: "Filesystem Timestamps", value: "Not recorded by this recovery method")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            RecoveryAnnotationView(store: store.examination)

            Button(action: store.previewSelected) {
                Label("Verify and Preview", systemImage: "doc.text.viewfinder")
                    .frame(maxWidth: .infinity)
            }
            .disabled(!store.canPreview)
            Button(action: store.exportSelected) {
                Label("Export to New File…", systemImage: "square.and.arrow.up")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!store.canExport)
            Text("The saved recovered file is checked against its size and SHA-256 before preview or export. Existing destination files are preserved.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let receipt = store.lastExport,
               receipt.sha256 == artifact.sha256, receipt.byteCount == artifact.byteCount {
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Last Export Receipt", systemImage: "doc.badge.checkmark")
                            .font(.headline)
                        RecoveryInspectorField(label: "Output Path", value: receipt.outputPath)
                        RecoveryInspectorField(label: "Exported Bytes", value: "\(receipt.byteCount.formatted()) bytes")
                        RecoveryInspectorField(label: "SHA-256 · exported file bytes", value: receipt.sha256, monospaced: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            ForEach(Array(artifact.warnings.enumerated()), id: \.offset) { _, warning in
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct RecoveryDocumentPreviewView: View {
    let artifact: CarvedArtifact
    @Bindable var store: RecoveryWorkspaceStore

    private var matchingAnalysis: DocumentAnalysis? {
        guard let analysis = store.analysis,
              analysis.sourceSHA256 == artifact.sha256,
              analysis.sourceByteCount == artifact.byteCount else { return nil }
        return analysis
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Verified Local Preview", systemImage: "doc.text.viewfinder")
                .font(.headline)
            Text("Isolated decoder · recovered files up to 128 MiB · bounded text and thumbnail")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Button(matchingAnalysis == nil ? "Verify and Preview" : "Verify and Reload", action: store.previewSelected)
                    .disabled(!store.canPreview)
                if store.isPreviewing {
                    ProgressView().controlSize(.small)
                    Button("Cancel", action: store.cancel)
                }
            }
            if let reason = store.documentUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let analysis = matchingAnalysis {
                DecodedDocumentContentView(analysis: analysis, contentQuery: $store.contentQuery, searchOutcome: store.searchOutcome)
            } else if !store.isPreviewing {
                Text("Load a preview to validate supported content. Source-byte mapping and content decoding are separate checks.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct DecodedDocumentContentView: View {
    let analysis: DocumentAnalysis
    @Binding var contentQuery: String
    let searchOutcome: DocumentSearchOutcome?
    @State private var selectedPageNumber = 1

    private var displayedPage: DocumentTextPage? {
        analysis.textPages.first(where: { $0.pageNumber == selectedPageNumber }) ?? analysis.textPages.first
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(statusLabel, systemImage: analysis.status == .decoded ? "checkmark.circle" : "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(analysis.status == .decoded ? Color.primary : Color.orange)
            RecoveryInspectorField(label: "Decoded Kind / MIME", value: "\(analysis.contentKind.rawValue.uppercased()) · \(analysis.mimeType)")
            if let format = analysis.officeFormat {
                RecoveryInspectorField(label: "Office Format", value: format.rawValue.uppercased())
            }
            if let validation = analysis.structuralValidation {
                Label(validation == .validated ? "Container structure validated" : "Signature recognition only",
                      systemImage: validation == .validated ? "checkmark.circle" : "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(validation == .validated ? Color.secondary : Color.orange)
                if validation == .signatureOnly {
                    Text("A signature match does not establish that the document body is readable.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if let failure = analysis.failureCode {
                RecoveryInspectorField(label: "Decoder Result Code", value: failure)
            }
            if analysis.status == .decoded {
                if let data = analysis.thumbnailPNG {
                    RecoveryThumbnailView(data: data)
                }
                if let width = analysis.pixelWidth, let height = analysis.pixelHeight {
                    Text("\(width.formatted()) × \(height.formatted()) pixels")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                if analysis.contentKind == .pdf, let pageCount = analysis.pageCount {
                    Text("\(pageCount.formatted()) PDF pages · \(analysis.textPages.count.formatted()) pages with extracted text records")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if analysis.contentKind == .office || analysis.contentKind == .archive,
                   let count = analysis.contentUnitCount {
                    Text("\(count.formatted()) \(contentUnitLabel) · \(analysis.textPages.count.formatted()) text records")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if !analysis.textPages.isEmpty {
                    textContent
                    RecoveryDocumentSearchView(analysis: analysis, contentQuery: $contentQuery, searchOutcome: searchOutcome)
                } else {
                    Text(analysis.contentKind == .image || analysis.contentKind == .pdf
                         ? "No text was extracted. Image text and scanned PDF pages require OCR, which this preview does not perform."
                         : "No text was extracted from supported content units. Review the structural result and decoder warnings.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text(analysis.status == .unsupported
                     ? "This format is not supported by the local preview decoder. Export the verified recovered bytes for examination in a suitable application."
                     : "The content could not be decoded successfully. A verified recovery byte map does not establish that a file is structurally intact.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if !analysis.rawMetadata.isEmpty {
                DisclosureGroup("Raw File Metadata · \(analysis.rawMetadata.count.formatted()) fields") {
                    ScrollView(.vertical) {
                        LazyVStack(alignment: .leading, spacing: 10) {
                            Text("Values are reported from the recovered file. Dates without an offset remain unzoned raw values; they are not filesystem timestamps.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            ForEach(analysis.rawMetadata) { metadata in
                                RecoveryInspectorField(label: metadata.name, value: metadata.value)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 240)
                    .accessibilityLabel("Raw file metadata values")
                    .padding(.top, 8)
                }
                .font(.caption)
            }
            ForEach(Array(analysis.warnings.enumerated()), id: \.offset) { _, warning in
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            DisclosureGroup("Preview Verification") {
                VStack(alignment: .leading, spacing: 8) {
                    RecoveryInspectorField(label: "Verified File Bytes", value: "\(analysis.sourceByteCount.formatted()) bytes")
                    RecoveryInspectorField(label: "SHA-256 · decoded input file bytes", value: analysis.sourceSHA256, monospaced: true)
                    Text("The image or PDF shown above is a bounded, re-encoded PNG thumbnail from the isolated decoder. Thumbnail appearance alone does not prove that every part of the original recovered file is readable.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 8)
            }
            .font(.caption)
        }
        .onChange(of: analysis.sourceSHA256) { _, _ in
            selectedPageNumber = analysis.textPages.first?.pageNumber ?? 1
        }
    }

    private var statusLabel: String {
        switch analysis.status {
        case .decoded: "Content Decoded"
        case .unsupported: "Unsupported Preview Format"
        case .failed: "Content Decode Failed"
        }
    }

    private var contentUnitLabel: String {
        if analysis.contentKind == .archive { return "archive members" }
        switch analysis.officeFormat {
        case .pptx, .ppt: return "slides"
        case .xlsx, .xls: return "worksheets"
        default: return "document bodies"
        }
    }

    private var textContent: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Extracted Text").font(.headline)
                Spacer(minLength: 8)
                if analysis.textPages.count > 1 {
                    Picker("Content unit", selection: $selectedPageNumber) {
                        ForEach(analysis.textPages) { page in
                            Text(DecodedDocumentReference.title(number: page.pageNumber, label: page.referenceLabel, kind: page.referenceKind))
                                .tag(page.pageNumber)
                        }
                    }
                    .labelsHidden()
                    .frame(maxWidth: 110)
                }
            }
            Label(analysis.textIsComplete ? "Extracted text records complete" : "Extracted text is incomplete",
                  systemImage: analysis.textIsComplete ? "checkmark.circle" : "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(analysis.textIsComplete ? Color.secondary : Color.orange)
            if let page = displayedPage {
                RecoveryExtractedTextView(page: page)
                if page.isTruncated {
                    Text("\(DecodedDocumentReference.title(number: page.pageNumber, label: page.referenceLabel, kind: page.referenceKind)) text reached the decoder limit.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
    }
}

private enum DecodedDocumentReference {
    static func title(number: Int, label: String?, kind: DocumentTextReferenceKind?) -> String {
        if let label, !label.isEmpty { return label }
        switch kind {
        case .page: return "Page \(number)"
        case .slide: return "Slide \(number)"
        case .sheet: return "Sheet \(number)"
        case .document: return "Document body \(number)"
        case .archiveMember: return "Archive member \(number)"
        case nil: return "Content unit \(number)"
        }
    }
}

/// Bound each rendered text slice independently of the decoder's overall limit.
/// References remain UTF-16 offsets in decoded page text, never evidence bytes.
private struct RecoveryExtractedTextView: View {
    let page: DocumentTextPage
    @State private var slice = 0
    private let sliceSize = 8_192

    private var text: NSString { page.text as NSString }
    private var lastSlice: Int { max(0, (text.length - 1) / sliceSize) }
    private var displayedSlice: Int { min(max(0, slice), lastSlice) }
    private var visibleRange: NSRange {
        let start = displayedSlice * sliceSize
        let range = NSRange(location: start, length: min(sliceSize, text.length - start))
        return text.length == 0 ? range : text.rangeOfComposedCharacterSequences(for: range)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            GroupBox {
                if visibleRange.length > sliceSize * 2 {
                    Text("This slice contains a composed character sequence above the display limit. Use text search or export the verified bytes to examine it.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    Text(verbatim: text.length == 0 ? "No text extracted on this page." : text.substring(with: visibleRange))
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            Text("\(DecodedDocumentReference.title(number: page.pageNumber, label: page.referenceLabel, kind: page.referenceKind)) · decoded UTF-16 range \(visibleRange.location.formatted())..<\(NSMaxRange(visibleRange).formatted())")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .monospacedDigit()
            if lastSlice > 0 {
                HStack {
                    Button { slice = max(0, displayedSlice - 1) } label: { Image(systemName: "chevron.left") }
                        .disabled(displayedSlice == 0)
                        .accessibilityLabel("Previous text slice")
                    Text("\(displayedSlice + 1) / \(lastSlice + 1)").monospacedDigit()
                    Button { slice = min(lastSlice, displayedSlice + 1) } label: { Image(systemName: "chevron.right") }
                        .disabled(displayedSlice == lastSlice)
                        .accessibilityLabel("Next text slice")
                }
                .font(.caption)
                .controlSize(.small)
            }
        }
        .onChange(of: page) { _, _ in slice = 0 }
    }
}

private struct RecoveryThumbnailView: View {
    let data: Data
    @State private var thumbnail: NSImage?

    var body: some View {
        GroupBox {
            if let thumbnail {
                Image(nsImage: thumbnail)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: .infinity, maxHeight: 260)
                    .accessibilityLabel("Decoded recovered-file thumbnail")
            } else {
                Text("Thumbnail is unavailable.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .task(id: data) { thumbnail = NSImage(data: data) }
    }
}

private struct RecoveryDocumentSearchView: View {
    let analysis: DocumentAnalysis
    @Binding var contentQuery: String
    let searchOutcome: DocumentSearchOutcome?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("Find text in this file", text: $contentQuery)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel("Find literal text in decoded file")
                .onExitCommand { contentQuery = "" }
            Text("Literal text search · case insensitive · extracted text only")
                .font(.caption2)
                .foregroundStyle(.secondary)
            if let outcome = searchOutcome, outcome.query == contentQuery, !outcome.query.isEmpty {
                Text("\(outcome.hits.count.formatted())\(outcome.hitLimitReached ? "+" : "") matches")
                    .font(.caption)
                    .monospacedDigit()
                if !outcome.searchedTextIsComplete || !analysis.textIsComplete {
                    Text("Text coverage is incomplete. No match does not establish that the original file lacks this text.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                if outcome.hitLimitReached {
                    Text("The hit limit was reached; additional matches are not displayed.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                ForEach(outcome.hits) { hit in
                    GroupBox {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(DecodedDocumentReference.title(number: hit.pageNumber, label: hit.referenceLabel, kind: hit.referenceKind)) · UTF-16 offset \(hit.utf16Offset.formatted())")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                            Text(verbatim: hit.snippet)
                                .font(.caption)
                                .textSelection(.enabled)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                Text("References are offsets in decoded content-unit text, not image byte offsets.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct RecoveryCandidateIntegrityView: View {
    let artifact: CarvedArtifact
    let result: CarvingResult?
    let store: RecoveryWorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Recovered File SHA-256").font(.headline)
                Spacer(minLength: 8)
                Button(action: store.copySelectedHash) { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .help("Copy recovered file SHA-256")
                    .accessibilityLabel("Copy recovered file SHA-256")
            }
            RecoveryInspectorField(label: "Scope · recovered-file-bytes", value: artifact.sha256, monospaced: true)
            Label(artifact.validationStatus == .sourceBytesVerified ? "Complete source-byte mapping verified" : "Source-byte mapping unverified",
                  systemImage: artifact.validationStatus == .sourceBytesVerified ? "checkmark.shield" : "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(artifact.validationStatus == .sourceBytesVerified ? Color.secondary : Color.orange)
            Text("Offsets refer to bytes in the selected single RAW image. They are not filesystem addresses or proof of original names, timestamps or deletion.")
                .font(.caption)
                .foregroundStyle(.secondary)
            RecoveryByteRunsView(title: "Verified RAW Byte Runs", runs: artifact.verifiedByteRuns, verified: true)
            RecoveryByteRunsView(title: "PhotoRec Reported Byte Runs", runs: artifact.reportedByteRuns, verified: false)
            if let result {
                DisclosureGroup("Saved Recovery Provenance") {
                    VStack(alignment: .leading, spacing: 10) {
                        RecoveryInspectorField(label: "Source SHA-256 · selected file bytes", value: result.sourceSHA256, monospaced: true)
                        RecoveryInspectorField(label: "Source Size", value: "\(result.sourceByteCount.formatted()) bytes")
                        RecoveryInspectorField(label: "PhotoRec Version", value: result.photoRecVersion)
                        RecoveryInspectorField(label: "PhotoRec Executable SHA-256", value: result.executableSHA256, monospaced: true)
                        RecoveryInspectorField(label: "Recovery Job ID", value: result.jobID.uuidString.lowercased(), monospaced: true)
                        RecoveryInspectorField(label: "Saved Result", value: result.savedAt.formatted(date: .abbreviated, time: .standard))
                        Text("Saved Result is the publication time of this recovery receipt, not a timestamp recovered from the evidence.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.top, 8)
                }
                .font(.caption)
            }
        }
    }
}

private struct RecoveryByteRunsView: View {
    let title: String
    let runs: [RecoveryByteRun]
    let verified: Bool
    @State private var page = 0
    private let pageSize = 32

    private var lastPage: Int { max(0, (runs.count - 1) / pageSize) }
    private var displayedPage: Int { min(max(0, page), lastPage) }
    private var visibleRange: Range<Int> {
        let start = displayedPage * pageSize
        return start..<min(start + pageSize, runs.count)
    }

    var body: some View {
        DisclosureGroup("\(title) · \(runs.count.formatted())") {
            VStack(alignment: .leading, spacing: 10) {
                if runs.isEmpty {
                    Text(verified ? "No verified source mapping is recorded." : "No source byte runs were reported.")
                        .foregroundStyle(.secondary)
                } else {
                    Text(verified ? "These source bytes were compared with the recovered file bytes."
                         : "These offsets are PhotoRec claims. Use the verified map to establish byte correspondence.")
                        .foregroundStyle(.secondary)
                    ForEach(visibleRange, id: \.self) { index in
                        let run = runs[index]
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Run \((index + 1).formatted()) · \(run.length.formatted()) bytes")
                                .foregroundStyle(.secondary)
                            Text("Output: \(run.outputOffset.formatted())..<\((run.outputOffset + run.length).formatted())")
                            Text("RAW: \(run.sourceOffset.formatted())..<\((run.sourceOffset + run.length).formatted())")
                        }
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                    }
                    if runs.count > pageSize {
                        HStack {
                            Button { page = max(0, displayedPage - 1) } label: { Image(systemName: "chevron.left") }
                                .disabled(displayedPage == 0)
                                .accessibilityLabel("Previous byte runs")
                            Text("\(displayedPage + 1) / \(lastPage + 1)").monospacedDigit()
                            Button { page = min(lastPage, displayedPage + 1) } label: { Image(systemName: "chevron.right") }
                                .disabled(displayedPage == lastPage)
                                .accessibilityLabel("Next byte runs")
                        }
                        .controlSize(.small)
                    }
                }
            }
            .padding(.top, 8)
        }
        .font(.caption)
        .onChange(of: runs) { _, _ in page = 0 }
    }
}

private struct RecoveryInspectorField: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(verbatim: value)
                .font(monospaced ? .system(.caption2, design: .monospaced) : .callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
