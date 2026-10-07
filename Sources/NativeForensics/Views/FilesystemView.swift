import ForensicsCore
import SwiftUI

struct FilesystemView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        VStack(spacing: 0) {
            FilesystemControlsView(workspace: workspace)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            Divider()
            if workspace.selectedEvidence == nil {
                ContentUnavailableView {
                    Label("Select an Evidence Image", systemImage: "externaldrive")
                } description: {
                    Text("Inspect an image, then select its evidence record to explore the filesystem.")
                } actions: {
                    Button("Inspect Disk Image…", action: workspace.chooseImage)
                        .disabled(!workspace.canInspectImage)
                }
            } else if let result = workspace.selectedFilesystemResult {
                FilesystemResultSummaryView(result: result)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                Divider()
                FilesystemTableView(workspace: workspace)
                Divider()
                FilesystemSelectionView(workspace: workspace)
            } else {
                ContentUnavailableView {
                    Label("Ready to Analyze", systemImage: "list.bullet.rectangle")
                } description: {
                    Text("Review Analysis Options, then read the filesystem. Source bytes are verified before and after analysis.")
                        .frame(maxWidth: 420)
                } actions: {
                    Button("Analyze Filesystem", action: workspace.analyzeSelectedImage)
                        .buttonStyle(.borderedProminent)
                        .disabled(!workspace.canAnalyzeFilesystem)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct FilesystemControlsView: View {
    @Bindable var workspace: WorkspaceStore
    @State private var optionsExpanded = false

    private var optionsSummary: String {
        let sector = workspace.engineSectorSize == 0 ? "Auto sector" : "\(workspace.engineSectorSize)-byte sector"
        return "\(workspace.engineImageType.uppercased()) · \(sector) · \(workspace.evidenceTimezone) · \(workspace.engineMaxFilesText) entries"
    }

    private var optionsChanged: Bool {
        guard let saved = workspace.selectedFilesystemResult else { return false }
        return saved.options != workspace.engineOptions
            || saved.sourcePaths != ([workspace.selectedEvidence?.sourcePath].compactMap { $0 }
                + workspace.additionalImageSegments.map(\.path))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Picker("Data source", selection: $workspace.selectedEvidenceID) {
                    Text("Select image").tag(nil as UUID?)
                    ForEach(workspace.currentCase?.manifest.evidence ?? [], id: \.id) { record in
                        Text(URL(fileURLWithPath: record.sourcePath).lastPathComponent)
                            .tag(Optional(record.id))
                    }
                }
                .disabled(workspace.isBusy)
                .frame(maxWidth: .infinity)
                Button(action: workspace.analyzeSelectedImage) {
                    Label("Analyze", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .help("Analyze the selected evidence image (⇧⌘A)")
                .disabled(!workspace.canAnalyzeFilesystem)
                Button(action: workspace.chooseExtractionDestination) {
                    Label("Extract…", systemImage: "square.and.arrow.up")
                }
                .help("Extract the selected file to a new destination (⇧⌘E)")
                .disabled(!workspace.canExtractFilesystemFile)
                Button(action: workspace.exportMatchingFilesystemFiles) {
                    Label("Export Matching Files (\(workspace.matchingExportableFiles.count.formatted()))…", systemImage: "folder.badge.plus")
                }
                .help("Export all matching regular files, including rows on other table pages, to a new folder. Source verification runs for every file.")
                .disabled(!workspace.canExtractAllMatched)
            }
            if workspace.filesystemBatchExport.isExporting || workspace.filesystemBatchExport.result != nil || workspace.filesystemBatchExport.errorMessage != nil {
                FilesystemBatchExportView(store: workspace.filesystemBatchExport)
            }
            DisclosureGroup(isExpanded: $optionsExpanded) {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 16) {
                        Picker("Image format", selection: $workspace.engineImageType) {
                            Text("Auto").tag("auto")
                            Text("Raw").tag("raw")
                            Text("EWF").tag("ewf")
                        }
                        Picker("Sector size", selection: $workspace.engineSectorSize) {
                            Text("Auto").tag(0)
                            Text("512 bytes").tag(512)
                            Text("4096 bytes").tag(4096)
                        }
                    }
                    HStack(alignment: .top, spacing: 16) {
                        VStack(alignment: .leading, spacing: 5) {
                            HStack(spacing: 5) {
                                Text("Evidence timezone")
                                Menu {
                                    Button("Asia/Bangkok") { workspace.evidenceTimezone = "Asia/Bangkok" }
                                    Button("UTC") { workspace.evidenceTimezone = "UTC" }
                                    Button("System: \(TimeZone.current.identifier)") {
                                        workspace.evidenceTimezone = TimeZone.current.identifier
                                    }
                                } label: {
                                    Image(systemName: "globe")
                                }
                                .menuStyle(.borderlessButton)
                                .fixedSize()
                                .help("Choose a timezone or enter an IANA identifier")
                            }
                            TextField("IANA timezone", text: $workspace.evidenceTimezone)
                                .textFieldStyle(.roundedBorder)
                                .accessibilityLabel("Evidence timezone")
                        }
                        .frame(maxWidth: .infinity)
                        VStack(alignment: .leading, spacing: 5) {
                            Text("Listing limit")
                            TextField("Maximum entries", text: $workspace.engineMaxFilesText)
                                .textFieldStyle(.roundedBorder)
                                .accessibilityLabel("Maximum filesystem entries")
                                .help("Include from 1 to 50,000 entries. Reaching the limit produces a partial result.")
                        }
                        .frame(width: 110)
                    }
                    Text("Evidence timezone interprets timestamps without a UTC offset. A listing limit of 1–50,000 bounds the saved result. Reanalyze to apply changed options.")
                        .foregroundStyle(.secondary)
                    ImageSegmentControlsView(workspace: workspace)
                }
                .font(.caption)
                .padding(.top, 10)
                .disabled(workspace.isBusy || workspace.isLoadingFilesystem)
            } label: {
                HStack(spacing: 12) {
                    Text("Analysis Options")
                        .fontWeight(.medium)
                        .fixedSize()
                    Text(optionsSummary)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(optionsSummary)
                    if !workspace.additionalImageSegments.isEmpty {
                        Text("\(workspace.additionalImageSegments.count + 1) source files")
                            .foregroundStyle(.secondary)
                            .fixedSize()
                            .help("Expand Analysis Options to review the exact image read order.")
                    }
                    Spacer(minLength: 0)
                }
            }
            .font(.caption)
            if TimeZone(identifier: workspace.evidenceTimezone) == nil {
                validationMessage("Enter a valid IANA timezone, such as Asia/Bangkok or UTC.")
            }
            if let message = workspace.engineMaxFilesValidationMessage {
                validationMessage(message)
            }
            if optionsChanged {
                Label("Options changed · Reanalyze to update the saved listing.", systemImage: "arrow.clockwise")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func validationMessage(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle")
            .font(.caption)
            .foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct FilesystemResultSummaryView: View {
    let result: EnumerationResult
    @State private var provenanceExpanded = false
    @State private var warningsExpanded = false

    private var hasWarning: Bool { result.status != .completed || !result.warnings.isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            DisclosureGroup(isExpanded: $provenanceExpanded) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Saved \(result.savedAt.formatted(date: .abbreviated, time: .shortened)) · \(result.image.imageType.uppercased()) · \(result.image.sectorSize)-byte sectors")
                    Text("Evidence timezone \(result.options.timezone) · listing limit \(result.options.maxFiles.formatted())")
                    Text("Historical result. Source hashes are checked again before extraction; reanalyze to refresh the listing.")
                }
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .padding(.top, 5)
            } label: {
                HStack {
                    Label(FilesystemFormatting.status(result.status), systemImage: hasWarning ? "exclamationmark.triangle" : "checkmark.circle")
                        .foregroundStyle(hasWarning ? Color.orange : Color.secondary)
                        .lineLimit(1)
                        .help(FilesystemFormatting.status(result.status))
                    Spacer(minLength: 8)
                    Text("\(result.files.count.formatted()) entries · \(result.volumes.count.formatted()) \(result.volumes.count == 1 ? "filesystem" : "filesystems")")
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                        .fixedSize()
                }
            }
            if let notice = FilesystemFormatting.reanalysisNotice(for: result) {
                Label(notice, systemImage: "arrow.clockwise")
                    .foregroundStyle(.orange)
            }
            if let warning = result.warnings.first {
                Text(warning)
                    .foregroundStyle(.orange)
                    .lineLimit(2)
                    .help(warning)
                    .textSelection(.enabled)
                DisclosureGroup("Review \(result.warnings.count.formatted()) analysis warnings", isExpanded: $warningsExpanded) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(Array(result.warnings.enumerated()), id: \.offset) { _, warning in
                                Text(warning).textSelection(.enabled)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .foregroundStyle(.orange)
                    .frame(maxHeight: 100)
                    .padding(.top, 5)
                }
            }
        }
        .font(.caption)
    }
}
