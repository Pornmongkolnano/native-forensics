import AppKit
import ForensicsCore
import SwiftUI

struct OpticalWorkspaceView: View {
    let workspace: WorkspaceStore

    var body: some View {
        VStack(spacing: 0) {
            OpticalControlsView(workspace: workspace)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            Divider()
            if let result = workspace.optical.result {
                OpticalResultSummaryView(result: result)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                Divider()
                OpticalFilesTableView(workspace: workspace)
                Divider()
                RecoveryRawHexView(store: workspace.recovery.examination)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
            } else {
                ContentUnavailableView {
                    Label(workspace.optical.isLoading ? "Loading Optical Result" : "Inspect UDF Optical History",
                          systemImage: "opticaldisc")
                } description: {
                    Text(workspace.optical.hasSource
                         ? "Read the supported UDF profile and its linked VAT snapshots. Current files, historical files and files beneath deleted directory entries retain their recorded paths and metadata."
                         : "Select a recorded RAW optical image to load a saved result or inspect supported UDF metadata.")
                        .frame(maxWidth: 450)
                } actions: {
                    if workspace.optical.isLoading {
                        ProgressView().controlSize(.small)
                    } else if workspace.optical.hasSource {
                        Button("Inspect Optical Image", action: workspace.optical.inspect)
                            .disabled(!workspace.optical.canInspect)
                    } else {
                        Button("Add Data Source…", action: workspace.chooseImage)
                            .disabled(!workspace.canInspectImage)
                    }
                }
            }
        }
    }
}

private struct OpticalControlsView: View {
    let workspace: WorkspaceStore
    private var store: OpticalWorkspaceStore { workspace.optical }

    private var isWorking: Bool {
        store.isLoading || store.isInspecting || store.isPreviewing || store.isExporting || store.isExportingReport || store.isExportingAutopsy || store.isFiltering
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Label("Optical Files and History", systemImage: "opticaldisc")
                        .font(.headline)
                    Text(store.hasSource ? store.selectedSourceFilename : "Select an evidence record")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(store.selectedSourceFilename)
                }
                Spacer(minLength: 8)
                Button(action: store.refresh) { Image(systemName: "arrow.clockwise") }
                    .disabled(!store.hasSource || isWorking)
                    .help("Reload the saved UDF inspection result")
                    .accessibilityLabel("Reload saved UDF inspection")
                Button(action: store.inspect) {
                    Label(store.result == nil ? "Inspect UDF" : "Inspect Again", systemImage: "play.circle")
                }
                .disabled(!store.canInspect)
            }
            HStack(alignment: .top, spacing: 12) {
                Text("Bounded UDF reader · one RAW image · 2,048-byte blocks · physical / virtual VAT profile")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                if store.result != nil {
                    Button(action: store.exportReport) {
                        Label("Export Report…", systemImage: "doc.text")
                    }
                    .disabled(!store.canExportReport)
                }
            }
            if store.result != nil {
                OpticalAutopsyExportView(workspace: workspace)
            }
            DisclosureGroup("Inspection Limits") {
                Text("\(store.options.maximumSnapshots.formatted()) snapshots · \(store.options.maximumFiles.formatted()) files · \(EvidenceFormatting.bytes(store.options.maximumSourceBytes)) input · \(EvidenceFormatting.bytes(store.options.maximumFileBytes)) per file · \(EvidenceFormatting.bytes(store.options.maximumPayloadBytes)) payload · \(store.options.timeoutSeconds.formatted()) seconds")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 6)
            }
            .font(.caption)
            if let reportURL = store.reportURL {
                HStack(spacing: 10) {
                    Label("Report saved: \(reportURL.lastPathComponent)", systemImage: "doc.badge.checkmark")
                        .font(.caption)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(reportURL.path)
                    Spacer(minLength: 0)
                    Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([reportURL]) }
                }
            }
            if let reason = store.inspectionUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if isWorking {
                HStack(spacing: 10) {
                    if let progress = store.progress, progress.totalBytes > 0 {
                        ProgressView(value: min(max(Double(progress.completedBytes) / Double(progress.totalBytes), 0), 1))
                            .frame(maxWidth: 180)
                        Text(OpticalViewFormatting.progressDescription(progress))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    } else {
                        ProgressView().controlSize(.small)
                        Text(store.statusMessage)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 0)
                    Button("Cancel", action: store.cancel)
                }
            } else {
                Text(store.statusMessage)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error = store.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        }
        .controlSize(.small)
    }
}

private struct OpticalResultSummaryView: View {
    let result: UDFInspectionResult

    private func count(_ state: UDFEntryState) -> Int {
        result.entries.filter { $0.state == state }.count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Label(result.volumeIdentifier.isEmpty ? "UDF \(result.udfRevision)" : result.volumeIdentifier,
                      systemImage: "opticaldisc")
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 0)
                Text("\(result.entries.count.formatted()) files · \(result.snapshots.count.formatted()) snapshots")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            .font(.caption)
            Text("Current \(count(.current).formatted()) · Historical \(count(.historical).formatted()) · Deleted ancestor \(count(.historicalDeletedAncestor).formatted()) · FID-deleted \(count(.fidDeleted).formatted())")
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
                .fixedSize(horizontal: false, vertical: true)
            DisclosureGroup("Inspection scope and limits") {
                VStack(alignment: .leading, spacing: 7) {
                    Text("UDF \(result.udfRevision) · \(result.blockSize.formatted())-byte blocks · \(result.profile)")
                    Text("Limits: \(result.options.maximumSnapshots.formatted()) snapshots · \(result.options.maximumFiles.formatted()) files · \(EvidenceFormatting.bytes(result.options.maximumFileBytes)) per file · \(EvidenceFormatting.bytes(result.options.maximumPayloadBytes)) payload · \(result.options.timeoutSeconds.formatted()) seconds")
                    Text("Source SHA-256 · selected RAW file bytes")
                        .foregroundStyle(.secondary)
                    Text(verbatim: result.sourceSHA256)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                    Text("Saved \(result.savedAt.formatted(date: .abbreviated, time: .standard)). This is the inspection receipt time, not a file timestamp.")
                        .foregroundStyle(.secondary)
                    ForEach(Array(result.limitations.enumerated()), id: \.offset) { _, limitation in
                        Label(limitation, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 7)
            }
            .font(.caption)
        }
    }
}

private struct OpticalFilesTableView: View {
    let workspace: WorkspaceStore
    @State private var page = 0
    private let pageSize = 100

    private var store: OpticalWorkspaceStore { workspace.optical }
    private var lastPage: Int { max(0, (store.rows.count - 1) / pageSize) }
    private var displayedPage: Int { min(max(0, page), lastPage) }
    private var pageRange: Range<Int> {
        let start = displayedPage * pageSize
        return start..<min(start + pageSize, store.rows.count)
    }
    private var pageRows: ArraySlice<UDFFileEntry> { store.rows[pageRange] }
    private var isFiltered: Bool { !store.searchText.isEmpty || store.stateFilter != .all }

    private func matchingAnalysis(_ entry: UDFFileEntry) -> DocumentAnalysis? {
        guard let analysis = store.analyses[entry.id],
              analysis.sourceSHA256 == entry.sha256,
              analysis.sourceByteCount == entry.byteCount else { return nil }
        return analysis
    }

    var body: some View {
        @Bindable var optical = store
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Find recorded path or SHA-256", text: $optical.searchText)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Find UDF recorded path or file SHA-256")
                    .onExitCommand { optical.searchText = "" }
                Picker("Namespace state", selection: $optical.stateFilter) {
                    Text("All States").tag(OpticalStateFilter.all)
                    Text("Current").tag(OpticalStateFilter.current)
                    Text("History").tag(OpticalStateFilter.history)
                    Text("Deleted Ancestor").tag(OpticalStateFilter.deletedAncestor)
                }
                .labelsHidden()
                .accessibilityLabel("UDF namespace state")
                .frame(width: 140)
                if optical.isFiltering {
                    ProgressView().controlSize(.small)
                        .accessibilityLabel("Filtering UDF files")
                }
                Text("\(optical.rows.count.formatted()) / \((optical.result?.entries.count ?? 0).formatted())")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                    .fixedSize()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            Table(pageRows, selection: $optical.selectedEntryID) {
                TableColumn("Recorded Name / Path") { entry in
                    VStack(alignment: .leading, spacing: 2) {
                        Label(entry.name, systemImage: "doc")
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(entry.originalPath)
                            .font(.caption2)
                            .foregroundStyle(optical.selectedEntryID == entry.id
                                ? Color(nsColor: .alternateSelectedControlTextColor).opacity(0.8) : Color.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    .padding(.vertical, 3)
                    .help(entry.originalPath)
                }
                .width(min: 150, ideal: 240, max: 450)
                TableColumn("State") { entry in
                    Label(OpticalViewFormatting.state(entry.state), systemImage: OpticalViewFormatting.stateIcon(entry.state))
                        .font(.caption)
                        .foregroundStyle(optical.selectedEntryID == entry.id
                            ? Color(nsColor: .alternateSelectedControlTextColor)
                            : entry.state == .current ? Color.secondary : Color.orange)
                }
                .width(118)
                TableColumn("Size") { entry in
                    Text(EvidenceFormatting.bytes(entry.byteCount))
                        .font(.caption)
                        .monospacedDigit()
                        .help("\(entry.byteCount.formatted()) file bytes")
                }
                .width(76)
                TableColumn("Decoder MIME") { entry in
                    if let analysis = matchingAnalysis(entry) {
                        Text(analysis.mimeType)
                            .font(.caption)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help("Byte-inspected MIME: \(analysis.mimeType) · decoder result: \(analysis.status.rawValue). MIME recognition is separate from successful content decoding.")
                    } else {
                        Text("Not inspected")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .help("Verify and Preview this file to inspect its MIME from file bytes. Its filename extension remains a hint.")
                    }
                }
                .width(min: 100, ideal: 135, max: 220)
                TableColumn("SHA-256") { entry in
                    Text(String(entry.sha256.prefix(12)) + "…")
                        .font(.system(.caption2, design: .monospaced))
                        .help("File-byte SHA-256: \(entry.sha256)")
                }
                .width(102)
            }
            .disabled(optical.isLoading || optical.isInspecting || optical.isExporting || optical.isExportingReport || optical.isExportingAutopsy || optical.isFiltering)
            .contextMenu(forSelectionType: String.self) { selection in
                if !optical.isFiltering, selection.count == 1, let id = selection.first,
                   pageRows.contains(where: { $0.id == id }) {
                    Button {
                        optical.selectedEntryID = id
                        workspace.showInspector = true
                    } label: {
                        Label("Show Recorded File Details", systemImage: "sidebar.right")
                    }
                    Button {
                        optical.selectedEntryID = id
                        optical.copySelectedHash()
                    } label: {
                        Label("Copy File SHA-256", systemImage: "doc.on.doc")
                    }
                }
            }
            .overlay {
                if optical.rows.isEmpty && !optical.isLoading && !optical.isFiltering {
                    ContentUnavailableView {
                        Label(isFiltered ? "No Matching Recorded Files" : "No File Entries Recorded", systemImage: "doc.text.magnifyingglass")
                    } description: {
                        Text(isFiltered ? "Try another path, hash or namespace state."
                             : "Review the inspection limitations. The bounded reader does not establish that the image contains no other files.")
                    }
                }
            }
            Divider()
            HStack(spacing: 10) {
                Text(optical.rows.isEmpty ? "0 files"
                     : "Files \((pageRange.lowerBound + 1).formatted())–\(pageRange.upperBound.formatted()) of \(optical.rows.count.formatted())")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                Spacer(minLength: 0)
                Button { changePage(to: displayedPage - 1) } label: { Label("Previous", systemImage: "chevron.left") }
                    .disabled(displayedPage == 0)
                Button { changePage(to: displayedPage + 1) } label: { Label("Next", systemImage: "chevron.right") }
                    .disabled(displayedPage == lastPage)
            }
            .font(.caption)
            .controlSize(.small)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .disabled(optical.isLoading || optical.isInspecting || optical.isExporting || optical.isExportingReport || optical.isExportingAutopsy || optical.isFiltering)
            .help("Search covers all recorded entries. The table displays up to \(pageSize) rows per page.")
        }
        .onChange(of: store.searchText) { _, _ in changePage(to: 0) }
        .onChange(of: store.stateFilter) { _, _ in changePage(to: 0) }
        .onChange(of: store.result?.jobID) { _, _ in changePage(to: 0) }
        .onChange(of: store.rows.count) { _, _ in
            if page != displayedPage { changePage(to: displayedPage) }
        }
    }

    private func changePage(to newPage: Int) {
        store.selectedEntryID = nil
        page = min(max(0, newPage), lastPage)
    }
}

enum OpticalViewFormatting {
    static func state(_ state: UDFEntryState) -> String {
        switch state {
        case .current: "Current"
        case .historical: "Historical"
        case .historicalDeletedAncestor: "Deleted ancestor"
        case .fidDeleted: "FID deleted"
        }
    }

    static func stateIcon(_ state: UDFEntryState) -> String {
        switch state {
        case .current: "doc"
        case .historical: "clock.arrow.circlepath"
        case .historicalDeletedAncestor: "folder.badge.minus"
        case .fidDeleted: "trash"
        }
    }

    static func extensionHint(_ entry: UDFFileEntry) -> String {
        let suffix = (entry.name as NSString).pathExtension
        return suffix.isEmpty ? "Unknown" : suffix.uppercased()
    }

    static func progressDescription(_ value: UDFInspectionProgress) -> String {
        if value.stage.hasPrefix("Exporting verified file") || value.stage.hasPrefix("Complete:") {
            return "\(value.stage) · \(value.files.formatted()) / \(value.totalBytes.formatted()) files"
        }
        if value.stage.hasPrefix("Reading UDF namespace") {
            return "\(value.stage) · \(value.files.formatted()) files recorded"
        }
        return "\(value.stage) · \(EvidenceFormatting.bytes(value.completedBytes)) / \(EvidenceFormatting.bytes(value.totalBytes)) · \(value.files.formatted()) files"
    }

    static func utc(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
