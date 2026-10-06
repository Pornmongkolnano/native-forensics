import AppKit
import ForensicsCore
import SwiftUI

struct FilesystemInspectorView: View {
    let workspace: WorkspaceStore
    @State private var pane: InspectorPane = .properties

    private enum InspectorPane: String, CaseIterable {
        case properties = "Properties"
        case integrity = "Integrity"
    }

    private var displayTimezone: String {
        workspace.timestampDisplayTimezone == "UTC" ? "UTC" : workspace.selectedFilesystemResult?.options.timezone ?? "UTC"
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                if let file = workspace.selectedFilesystemFile {
                    HStack(alignment: .top, spacing: 10) {
                        ForensicFileIcon(file: file, size: 28)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(file.name.isEmpty ? file.path : file.name)
                                .font(.headline)
                                .lineLimit(2)
                                .truncationMode(.middle)
                                .help(file.path)
                            Text(file.isDirectory ? "Directory" : "Filesystem file")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if file.isDeleted {
                        Label("Deleted metadata does not guarantee intact contents. Verify the extracted bytes.", systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } else {
                    Label("File Inspector", systemImage: "doc.text.magnifyingglass")
                        .font(.headline)
                }
                if let result = workspace.selectedFilesystemResult,
                   result.status != .completed || !result.warnings.isEmpty {
                    Label("\(FilesystemFormatting.status(result.status)) · \(result.warnings.count.formatted()) \(result.warnings.count == 1 ? "warning" : "warnings")", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .help("Review analysis warnings in the Filesystem view before using these results.")
                }
                if workspace.extractionReceipt != nil && !workspace.extractionReceiptIsVerified {
                    Label("Extraction is unverified. Review the Integrity tab before using the output.", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Picker("Inspector information", selection: $pane) {
                    ForEach(InspectorPane.allCases, id: \.self) { pane in
                        Text(pane.rawValue).tag(pane)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .accessibilityLabel("Inspector information")
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 16) {
                    if pane == .properties {
                        if let file = workspace.selectedFilesystemFile {
                            FilesystemFileDetailsView(file: file, displayTimezone: displayTimezone)
                            Button(action: workspace.chooseExtractionDestination) {
                                Label("Extract to New File…", systemImage: "square.and.arrow.up")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(!workspace.canExtractFilesystemFile)
                            Button(action: workspace.openAssistant) {
                                Label("Analyze with Codex…", systemImage: "sparkles")
                                    .frame(maxWidth: .infinity)
                            }
                            .disabled(!workspace.canOpenAssistant)
                        } else {
                            Text("Select a file to inspect its metadata, timestamps and extraction options.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        if let receipt = workspace.extractionReceipt {
                            FilesystemExtractionReceiptView(receipt: receipt, verified: workspace.extractionReceiptIsVerified)
                        }
                        if let result = workspace.selectedFilesystemResult {
                            FilesystemAnalysisDetailsView(result: result)
                        } else {
                            Text("Analyze an evidence image to inspect recorded source hashes and engine provenance.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onChange(of: workspace.selectedEvidenceID) { _, _ in pane = .properties }
        .onChange(of: workspace.extractionReceipt) { _, receipt in
            if receipt != nil { pane = .integrity }
        }
    }
}

private struct FilesystemFileDetailsView: View {
    let file: FilesystemEntry
    let displayTimezone: String
    @State private var metadataExpanded = false
    @State private var timestampsExpanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            InspectorField(label: "Full Path", value: file.path)
                .help(file.path)
            HStack(alignment: .top, spacing: 20) {
                InspectorField(label: "Size", value: EvidenceFormatting.bytes(file.size))
                    .help("\(file.size.formatted()) bytes")
                VStack(alignment: .leading, spacing: 4) {
                    Text("Allocation").font(.caption).foregroundStyle(.secondary)
                    Label(file.isDeleted ? "Deleted" : "Allocated", systemImage: file.isDeleted ? "trash" : "doc")
                        .foregroundStyle(file.isDeleted ? Color.orange : Color.primary)
                }
            }
            GroupBox {
                DisclosureGroup("Timestamps · \(displayTimezone)", isExpanded: $timestampsExpanded) {
                    VStack(alignment: .leading, spacing: 10) {
                        timestamp("Created", seconds: file.createdEpoch, nanoseconds: file.createdNanoseconds)
                        timestamp("Modified", seconds: file.modifiedEpoch, nanoseconds: file.modifiedNanoseconds)
                        timestamp("Accessed", seconds: file.accessedEpoch, nanoseconds: file.accessedNanoseconds)
                        timestamp("Metadata Changed", seconds: file.changedEpoch, nanoseconds: file.changedNanoseconds)
                        Text("Recorded seconds and nanoseconds are retained. Display timezone changes presentation only.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.top, 8)
                }
                .font(.caption)
            }
            GroupBox {
                DisclosureGroup("Filesystem Address", isExpanded: $metadataExpanded) {
                    VStack(alignment: .leading, spacing: 10) {
                        InspectorField(label: "Exact Size", value: "\(file.size.formatted()) bytes")
                        InspectorField(label: "Metadata Address / Inode", value: String(file.metaAddress))
                        InspectorField(label: "Filesystem Offset", value: "\(file.fsOffsetBytes.formatted()) bytes")
                        if let attributeType = file.attributeType {
                            InspectorField(label: "Attribute", value: "Type \(attributeType) · ID \(file.attributeID.map(String.init) ?? "not recorded")")
                        }
                    }
                    .padding(.top, 8)
                }
                .font(.caption)
            }
        }
    }

    private func timestamp(_ title: String, seconds: Int64?, nanoseconds: Int32) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).foregroundStyle(.secondary)
            Text(FilesystemFormatting.timestamp(seconds, in: displayTimezone))
                .monospacedDigit()
                .textSelection(.enabled)
            Text(FilesystemFormatting.rawTime(seconds, nanoseconds: nanoseconds))
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }
}

private struct FilesystemAnalysisDetailsView: View {
    let result: EnumerationResult
    @State private var analysisExpanded = false
    @State private var hashesExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Saved Analysis", systemImage: "externaldrive.badge.checkmark")
                .font(.headline)
            Label(FilesystemFormatting.status(result.status), systemImage: result.status == .completed && result.warnings.isEmpty ? "checkmark.circle" : "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(result.status == .completed && result.warnings.isEmpty ? Color.secondary : Color.orange)
            Text("\(result.savedAt.formatted(date: .abbreviated, time: .shortened)) · \(result.files.count.formatted()) entries")
                .font(.caption)
                .foregroundStyle(.secondary)
            GroupBox {
                DisclosureGroup("Analysis Provenance", isExpanded: $analysisExpanded) {
                    VStack(alignment: .leading, spacing: 10) {
                        InspectorField(label: "Engine", value: result.engineVersion)
                        InspectorField(label: "Resolved Image Format", value: result.image.imageType.uppercased())
                        InspectorField(label: "Sector Size", value: "\(result.image.sectorSize) bytes")
                        InspectorField(label: "Logical Image Size", value: "\(EvidenceFormatting.bytes(result.image.logicalSize)) (\(result.image.logicalSize.formatted()) bytes)")
                        InspectorField(label: "Evidence Timezone", value: result.options.timezone)
                        InspectorField(label: "Listing Limit", value: result.options.maxFiles.formatted())
                        ForEach(result.volumes) { volume in
                            InspectorField(label: "Filesystem at \(volume.offsetBytes.formatted()) bytes", value: volume.filesystem)
                        }
                        Text("Historical analysis. Source hashes are checked again before extraction.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.top, 8)
                }
                .font(.caption)
            }
            GroupBox {
                DisclosureGroup("Image Integrity", isExpanded: $hashesExpanded) {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        if let hash = result.image.logicalSha256 {
                            InspectorHashField(label: "Logical Image SHA-256", hash: hash)
                            Text("Scope: logical-image-bytes, after decompression. This differs from the selected container-file SHA-256 in Evidence.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        ForEach(result.sourcePaths, id: \.self) { path in
                            if let hash = result.sourceFileHashes[path] {
                                InspectorHashField(label: "Container File SHA-256 · \(URL(fileURLWithPath: path).lastPathComponent)", hash: hash)
                                    .help(path)
                            }
                        }
                        Text("\(result.sourcePaths.count.formatted()) ordered source files. Each container hash covers one file's bytes before decompression.")
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

private struct FilesystemExtractionReceiptView: View {
    let receipt: ExtractionResult
    let verified: Bool

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Label(verified ? "Last Extraction Receipt" : "Unverified Extraction Receipt", systemImage: verified ? "doc.badge.checkmark" : "exclamationmark.triangle")
                    .font(.headline)
                    .foregroundStyle(verified ? Color.primary : Color.orange)
                InspectorField(label: "Output Path", value: receipt.outputPath)
                InspectorField(label: "Extracted Bytes", value: receipt.byteCount.formatted())
                InspectorHashField(label: "Extracted File SHA-256", hash: receipt.sha256)
                Text(verified
                     ? "Scope: extracted-file-bytes. Source verification completed after extraction."
                     : "Scope: extracted-file-bytes. Post-extraction source verification did not complete; review the error before using this output.")
                    .font(.caption)
                    .foregroundStyle(verified ? Color.secondary : Color.orange)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct InspectorField: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value)
                .font(.callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct InspectorHashField: View {
    let label: String
    let hash: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                Spacer(minLength: 8)
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(hash, forType: .string)
                } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .help("Copy \(label)")
                    .accessibilityLabel("Copy \(label)")
            }
            Text(hash)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
