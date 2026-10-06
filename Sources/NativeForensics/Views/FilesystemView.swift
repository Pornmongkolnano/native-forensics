import ForensicsCore
import SwiftUI

struct FilesystemView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        VStack(spacing: 0) {
            FilesystemControlsView(workspace: workspace)
                .padding(16)
            Divider()
            if workspace.selectedEvidence == nil {
                ContentUnavailableView {
                    Label("Select an Evidence Image", systemImage: "externaldrive")
                } description: {
                    Text("Inspect an image first, then select its evidence record for filesystem analysis.")
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
            } else {
                ContentUnavailableView {
                    Label("Filesystem Not Analyzed", systemImage: "list.bullet.rectangle")
                } description: {
                    Text("Choose the image format, sector size, evidence timezone and listing limit, then analyze this image. Source bytes are verified before and after analysis.")
                        .frame(maxWidth: 470)
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

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Picker("Evidence", selection: $workspace.selectedEvidenceID) {
                    Text("Select image").tag(nil as UUID?)
                    ForEach(workspace.currentCase?.manifest.evidence ?? [], id: \.id) { record in
                        Text(URL(fileURLWithPath: record.sourcePath).lastPathComponent)
                            .tag(Optional(record.id))
                    }
                }
                .disabled(workspace.isBusy)
                Spacer(minLength: 12)
                Button("Analyze", action: workspace.analyzeSelectedImage)
                    .disabled(!workspace.canAnalyzeFilesystem)
                Button("Extract File…", action: workspace.chooseExtractionDestination)
                    .disabled(!workspace.canExtractFilesystemFile)
            }
            HStack(spacing: 16) {
                Picker("Image", selection: $workspace.engineImageType) {
                    Text("Auto").tag("auto")
                    Text("Raw").tag("raw")
                    Text("EWF").tag("ewf")
                }
                .frame(maxWidth: 190)
                Picker("Sector", selection: $workspace.engineSectorSize) {
                    Text("Auto").tag(0)
                    Text("512 bytes").tag(512)
                    Text("4096 bytes").tag(4096)
                }
                .frame(maxWidth: 220)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 5) {
                        Text("Evidence timezone")
                            .font(.caption)
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
                        .help("Choose a common timezone or enter an IANA timezone identifier")
                    }
                    TextField("IANA timezone", text: $workspace.evidenceTimezone)
                        .textFieldStyle(.roundedBorder)
                        .frame(minWidth: 140, maxWidth: 230)
                }
            }
            .disabled(workspace.isBusy || workspace.isLoadingFilesystem)
            if TimeZone(identifier: workspace.evidenceTimezone) == nil {
                Label("Enter a valid IANA timezone, such as Asia/Bangkok or UTC.", systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("Listing limit")
                TextField("Maximum entries", text: $workspace.engineMaxFilesText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 90)
                    .accessibilityLabel("Maximum filesystem entries")
                    .help("Maximum number of entries to include in a filesystem listing, from 1 to 50,000.")
                Text("1–50,000 entries")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .disabled(workspace.isBusy || workspace.isLoadingFilesystem)
            if let message = workspace.engineMaxFilesValidationMessage {
                Label(message, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            Text("Reaching the listing limit saves a partial result. Increase the limit and reanalyze to include more entries.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("Evidence timezone interprets timestamps that lack a UTC offset. Display timezone changes only how recorded times are shown. Reanalyze to apply changed options.")
                .font(.caption)
                .foregroundStyle(.secondary)
            ImageSegmentControlsView(workspace: workspace)
        }
    }
}

private struct FilesystemResultSummaryView: View {
    let result: EnumerationResult

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(FilesystemFormatting.status(result.status), systemImage: result.status == .completed && result.warnings.isEmpty ? "checkmark.circle" : "exclamationmark.triangle")
                    .foregroundStyle(result.status == .completed && result.warnings.isEmpty ? Color.secondary : Color.orange)
                Spacer()
                Text("\(result.files.count) entries · \(result.volumes.count) filesystems")
                    .monospacedDigit()
            }
            .font(.caption)
            Text("Saved analysis · \(result.image.imageType.uppercased()) · \(result.image.sectorSize)-byte sectors · evidence timezone \(result.options.timezone) · listing limit \(result.options.maxFiles.formatted())")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("Historical result. Source hashes are checked again before extraction; reanalyze to refresh the listing.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if result.engineVersion == "0.1.0-tsk4.15.0" {
                Label("Reanalyze this image to apply timestamp validation and include NTFS directory streams.", systemImage: "arrow.clockwise")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            if !result.warnings.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(Array(result.warnings.enumerated()), id: \.offset) { _, warning in
                            Text(warning).textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.caption)
                .foregroundStyle(.orange)
                .frame(maxHeight: 100)
            }
        }
    }
}
