import AppKit
import ForensicsCore
import SwiftUI

struct FilesystemInspectorView: View {
    let workspace: WorkspaceStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Label("Filesystem Inspector", systemImage: "info.circle")
                    .font(.headline)

                if let result = workspace.selectedFilesystemResult {
                    field("Analysis Status", FilesystemFormatting.status(result.status))
                    field("Evidence Timezone", result.options.timezone)
                    field("Engine", result.engineVersion)
                    field("Resolved Image Format", result.image.imageType.uppercased())
                    field("Sector Size", "\(result.image.sectorSize) bytes")
                    field("Logical Image Size", "\(EvidenceFormatting.bytes(result.image.logicalSize)) (\(result.image.logicalSize) bytes)")
                    if let hash = result.image.logicalSha256 {
                        hashField("Logical Image SHA-256", hash: hash)
                        Text("Scope: logical-image-bytes, after decompression. This is separate from the selected container-file SHA-256 in Evidence.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if result.sourcePaths.count > 1 {
                        field("Image Segments", "\(result.sourcePaths.count) ordered source files")
                        ForEach(result.sourcePaths, id: \.self) { path in
                            if let hash = result.sourceFileHashes[path] {
                                hashField("Container File SHA-256 — \(URL(fileURLWithPath: path).lastPathComponent)", hash: hash)
                            }
                        }
                        Text("Each container-file hash covers exactly one ordered segment, before decompression.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(result.volumes) { volume in
                        field("Filesystem at \(volume.offsetBytes) bytes", volume.filesystem)
                    }
                    Divider()
                }

                if let file = workspace.selectedFilesystemFile {
                    field("File Path", file.path)
                    field("Allocation", file.isDeleted ? "Deleted filesystem entry" : "Allocated filesystem entry")
                    if file.isDeleted {
                        Text("Deleted metadata does not guarantee that file contents are intact. Verify any extracted bytes.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    field("Size", "\(EvidenceFormatting.bytes(file.size)) (\(file.size) bytes)")
                    field("Metadata Address / Inode", String(file.metaAddress))
                    field("Filesystem Offset", "\(file.fsOffsetBytes) bytes")
                    if let attributeType = file.attributeType {
                        field("Attribute", "Type \(attributeType) · ID \(file.attributeID.map(String.init) ?? "not recorded")")
                    }
                    field("Created — Unix Time", FilesystemFormatting.rawTime(file.createdEpoch, nanoseconds: file.createdNanoseconds))
                    field("Modified — Unix Time", FilesystemFormatting.rawTime(file.modifiedEpoch, nanoseconds: file.modifiedNanoseconds))
                    field("Accessed — Unix Time", FilesystemFormatting.rawTime(file.accessedEpoch, nanoseconds: file.accessedNanoseconds))
                    field("Metadata Changed — Unix Time", FilesystemFormatting.rawTime(file.changedEpoch, nanoseconds: file.changedNanoseconds))
                    Text("Recorded seconds and nanoseconds are retained. The table's display timezone changes presentation only.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    Button("Extract to New File…", action: workspace.chooseExtractionDestination)
                        .disabled(!workspace.canExtractFilesystemFile)
                } else {
                    Text("Select a file to inspect its metadata address, timestamps and extraction options.")
                        .foregroundStyle(.secondary)
                }

                if let receipt = workspace.extractionReceipt {
                    Divider()
                    Label(workspace.extractionReceiptIsVerified ? "Extraction Receipt" : "Unverified Extraction Receipt", systemImage: workspace.extractionReceiptIsVerified ? "doc.badge.checkmark" : "exclamationmark.triangle")
                        .font(.headline)
                        .foregroundStyle(workspace.extractionReceiptIsVerified ? Color.primary : Color.orange)
                    field("Output Path", receipt.outputPath)
                    field("Extracted Bytes", String(receipt.byteCount))
                    hashField("Extracted File SHA-256", hash: receipt.sha256)
                    Text(workspace.extractionReceiptIsVerified
                         ? "Scope: extracted-file-bytes. Source verification completed after extraction."
                         : "Scope: extracted-file-bytes. Post-extraction source verification did not complete; review the error before using this output.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func field(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func hashField(_ label: String, hash: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(label).font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(hash, forType: .string)
                } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .help("Copy \(label)")
            }
            Text(hash)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
