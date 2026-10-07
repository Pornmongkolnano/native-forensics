import AppKit
import ForensicsCore
import SwiftUI

struct RecoveryWorkspaceView: View {
    let workspace: WorkspaceStore

    var body: some View {
        VStack(spacing: 0) {
            RecoveryControlsView(store: workspace.recovery)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            RecoveryRawHexView(store: workspace.recovery.examination)
                .padding(.horizontal, 16)
                .padding(.bottom, 12)
            Divider()
            if let result = workspace.recovery.result {
                RecoveryResultSummaryView(result: result)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                Divider()
                RecoveryCandidatesTableView(workspace: workspace)
            } else {
                ContentUnavailableView {
                    Label(workspace.recovery.isLoading ? "Loading Recovery Result" : "Recover File Candidates",
                          systemImage: "doc.badge.arrow.up")
                } description: {
                    Text(workspace.recovery.hasSource
                         ? "Scan the whole selected RAW image for file signatures. Recovered names and format hints come from PhotoRec; deletion state and original filesystem paths remain unknown."
                         : "Select a recorded evidence image to load its saved recovery result or start a signature scan.")
                        .frame(maxWidth: 450)
                } actions: {
                    if workspace.recovery.isLoading {
                        ProgressView().controlSize(.small)
                    } else if workspace.recovery.hasSource {
                        Button("Recover File Candidates", action: workspace.recovery.beginRecovery)
                            .disabled(!workspace.recovery.canRecover)
                    } else {
                        Button("Add Data Source…", action: workspace.chooseImage)
                            .disabled(!workspace.canInspectImage)
                    }
                }
            }
        }
    }
}

private struct RecoveryControlsView: View {
    @Bindable var store: RecoveryWorkspaceStore

    private var isWorking: Bool {
        store.isLoading || store.isRecovering || store.isPreviewing || store.isExporting || store.isFiltering
            || store.examination.hasActiveWork
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Label("Signature Recovery", systemImage: "doc.badge.arrow.up")
                        .font(.headline)
                    Text(store.hasSource ? store.selectedSourceFilename : "Select an evidence record")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(store.selectedSourceFilename)
                }
                Spacer(minLength: 8)
                Button(action: store.examination.exportReport) {
                    Label("Export Report", systemImage: "doc.richtext")
                }
                .disabled(!store.examination.canExportReport || store.hasActiveWork)
                .help("Export hashes, retained decoder results and saved examiner assessments to a new Markdown file")
                Button(action: store.refresh) {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(!store.hasSource || isWorking)
                .help("Reload the saved recovery result")
                .accessibilityLabel("Reload saved recovery result")
                Button(action: store.beginRecovery) {
                    Label(store.result == nil ? "Recover Files" : "Run New Recovery", systemImage: "play.circle")
                }
                .disabled(!store.canRecover)
            }
            DisclosureGroup("Whole RAW Image · Recovery Limits") {
                Text("\(store.options.maximumFiles.formatted()) files · \(EvidenceFormatting.bytes(store.options.maximumOutputBytes)) total output · \(EvidenceFormatting.bytes(store.options.maximumArtifactBytes)) per file · \(EvidenceFormatting.bytes(store.options.maximumInputBytes)) input · \(store.options.timeout.formatted()) seconds")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 6)
            }
            .font(.caption)
            if let reason = store.recoveryUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if isWorking {
                HStack(spacing: 10) {
                    if let progress = store.progress, let total = progress.total, total > 0 {
                        ProgressView(value: min(max(Double(progress.completed) / Double(total), 0), 1))
                            .frame(maxWidth: 180)
                    } else {
                        ProgressView().controlSize(.small)
                    }
                    Text(progressLabel)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .monospacedDigit()
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

    private var progressLabel: String {
        if store.examination.hasActiveWork { return store.examination.statusMessage }
        guard let progress = store.progress else {
            return store.statusMessage
        }
        return "\(progress.stage): \(progress.completed.formatted())\(progress.total.map { " of \($0.formatted())" } ?? "") \(progress.unit)"
    }
}

private struct RecoveryResultSummaryView: View {
    let result: CarvingResult

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 14) {
                Label(result.status == .completed ? "Scan Completed" : "Partial Recovery Result",
                      systemImage: result.status == .completed ? "checkmark.circle" : "exclamationmark.triangle")
                    .foregroundStyle(result.status == .completed ? Color.secondary : Color.orange)
                Text("\(result.artifacts.count.formatted()) candidates")
                    .monospacedDigit()
                Spacer(minLength: 0)
                Text("Saved \(result.savedAt.formatted(date: .abbreviated, time: .shortened))")
                    .foregroundStyle(.secondary)
            }
            .font(.caption)
            DisclosureGroup("Method and limits") {
                VStack(alignment: .leading, spacing: 7) {
                    Text("Whole single RAW image · PhotoRec signature search · source is read-only")
                    Text("Limits: \(result.options.maximumFiles.formatted()) files · \(EvidenceFormatting.bytes(result.options.maximumOutputBytes)) output · \(EvidenceFormatting.bytes(result.options.maximumArtifactBytes)) per file · \(result.options.timeout.formatted()) seconds")
                    Text("Source SHA-256 · selected file bytes")
                        .foregroundStyle(.secondary)
                    Text(verbatim: result.sourceSHA256)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                    Text("Signature recovery may include allocated files, duplicate content, incomplete files and false positives. A successful scan does not establish that every recoverable file was found.")
                        .foregroundStyle(.secondary)
                    ForEach(Array(result.warnings.enumerated()), id: \.offset) { _, warning in
                        Label(warning, systemImage: "exclamationmark.triangle")
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

private struct RecoveryCandidatesTableView: View {
    let workspace: WorkspaceStore
    @State private var page = 0
    private let pageSize = 100

    private var store: RecoveryWorkspaceStore { workspace.recovery }
    private var lastPage: Int { max(0, (store.rows.count - 1) / pageSize) }
    private var displayedPage: Int { min(max(0, page), lastPage) }
    private var pageRange: Range<Int> {
        let start = displayedPage * pageSize
        return start..<min(start + pageSize, store.rows.count)
    }
    private var pageRows: ArraySlice<CarvedArtifact> { store.rows[pageRange] }
    private var isFiltered: Bool { !store.searchText.isEmpty || store.formatFilter != "all" }

    var body: some View {
        @Bindable var recovery = store
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Find recovered name or SHA-256", text: $recovery.searchText)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Find recovered filename or SHA-256")
                    .onExitCommand { recovery.searchText = "" }
                Picker("Format hint", selection: $recovery.formatFilter) {
                    Text("All Hints").tag("all")
                    ForEach(recovery.formatHints, id: \.self) { hint in
                        Text(hint.isEmpty ? "Unknown hint" : hint.uppercased()).tag(hint)
                    }
                }
                .labelsHidden()
                .frame(width: 112)
                .help("Filter by PhotoRec filename extension; the decoder confirms supported content separately.")
                if recovery.isFiltering {
                    ProgressView().controlSize(.small)
                        .accessibilityLabel("Filtering recovery candidates")
                }
                Text("\(recovery.rows.count.formatted()) / \((recovery.result?.artifacts.count ?? 0).formatted())")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                    .fixedSize()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            Table(pageRows, selection: $recovery.selectedArtifactID) {
                TableColumn("Recovered Name") { artifact in
                    Label(artifact.filename, systemImage: "doc")
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help("PhotoRec recovery filename: \(artifact.filename)")
                }
                .width(min: 150, ideal: 235, max: 500)
                TableColumn("Size") { artifact in
                    Text(EvidenceFormatting.bytes(artifact.byteCount))
                        .font(.caption)
                        .monospacedDigit()
                        .help("\(artifact.byteCount.formatted()) recovered bytes")
                }
                .width(76)
                TableColumn("Hint") { artifact in
                    Text(artifact.formatHint.isEmpty ? "Unknown" : artifact.formatHint.uppercased())
                        .font(.caption)
                        .help(artifact.formatHintScope)
                }
                .width(64)
                TableColumn("Source Bytes") { artifact in
                    Label(artifact.validationStatus == .sourceBytesVerified ? "Verified" : "Unverified",
                          systemImage: artifact.validationStatus == .sourceBytesVerified ? "checkmark.shield" : "questionmark.circle")
                        .font(.caption)
                        .foregroundStyle(recovery.selectedArtifactID == artifact.id
                            ? Color(nsColor: .alternateSelectedControlTextColor)
                            : artifact.validationStatus == .sourceBytesVerified ? Color.secondary : Color.orange)
                        .help("Byte mapping verification is separate from successful content decoding.")
                }
                .width(102)
                TableColumn("Deletion") { _ in
                    Text("Unknown").font(.caption)
                }
                .width(72)
            }
            .disabled(recovery.isLoading || recovery.isRecovering || recovery.isExporting || recovery.isFiltering)
            .contextMenu(forSelectionType: UUID.self) { selection in
                if !recovery.isFiltering, selection.count == 1, let id = selection.first,
                   pageRows.contains(where: { $0.id == id }) {
                    Button {
                        recovery.selectedArtifactID = id
                        workspace.showInspector = true
                    } label: {
                        Label("Show Candidate Details", systemImage: "sidebar.right")
                    }
                    Button {
                        recovery.selectedArtifactID = id
                        recovery.previewSelected()
                        workspace.showInspector = true
                    } label: {
                        Label("Verify and Preview", systemImage: "doc.text.viewfinder")
                    }
                    .disabled(recovery.isLoading || recovery.isRecovering || recovery.isPreviewing || recovery.isExporting || recovery.isFiltering)
                }
            }
            .overlay {
                if recovery.rows.isEmpty && !recovery.isLoading && !recovery.isFiltering {
                    ContentUnavailableView {
                        Label(isFiltered ? "No Matching Candidates" : "No Candidates Recorded", systemImage: "doc.text.magnifyingglass")
                    } description: {
                        Text(isFiltered ? "Try another filename, hash or format hint."
                             : "Review the scan status and warnings. An empty result does not establish that no recoverable content exists.")
                    }
                }
            }
            Divider()
            HStack(spacing: 10) {
                Text(recovery.rows.isEmpty ? "0 candidates"
                     : "Candidates \((pageRange.lowerBound + 1).formatted())–\(pageRange.upperBound.formatted()) of \(recovery.rows.count.formatted())")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                Spacer(minLength: 0)
                Button { changePage(to: displayedPage - 1) } label: { Label("Previous", systemImage: "chevron.left") }
                    .disabled(displayedPage == 0)
                Button { changePage(to: displayedPage + 1) } label: { Label("Next", systemImage: "chevron.right") }
                    .disabled(displayedPage == lastPage)
            }
            .disabled(recovery.isLoading || recovery.isRecovering || recovery.isExporting || recovery.isFiltering)
            .font(.caption)
            .controlSize(.small)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .help("Search covers all candidates. The table displays up to \(pageSize) rows per page.")
        }
        .onChange(of: store.searchText) { _, _ in changePage(to: 0) }
        .onChange(of: store.formatFilter) { _, _ in changePage(to: 0) }
        .onChange(of: store.result?.jobID) { _, _ in changePage(to: 0) }
        .onChange(of: store.rows.count) { _, _ in
            if page != displayedPage { changePage(to: displayedPage) }
        }
    }

    private func changePage(to newPage: Int) {
        store.selectedArtifactID = nil
        page = min(max(0, newPage), lastPage)
    }
}
