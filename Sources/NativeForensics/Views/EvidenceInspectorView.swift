import AppKit
import ForensicsCore
import SwiftUI

struct EvidenceInspectorView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        Group {
            if let evidence = workspace.selectedEvidence {
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        Label("Evidence Inspector", systemImage: "info.circle")
                            .font(.headline)

                        field("Source File", URL(fileURLWithPath: evidence.sourcePath).lastPathComponent)
                        field("Source Path", evidence.sourcePath)

                        HStack(alignment: .top) {
                            field("Container", EvidenceFormatting.container(evidence.container))
                            Spacer()
                            field("Status", "Inspected file")
                        }

                        field("File Size", "\(EvidenceFormatting.bytes(evidence.byteCount)) (\(evidence.byteCount) bytes)")

                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text("Selected File SHA-256")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Spacer()
                                Button {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(evidence.sha256, forType: .string)
                                } label: {
                                    Image(systemName: "doc.on.doc")
                                }
                                .buttonStyle(.borderless)
                                .help("Copy selected file SHA-256")
                            }
                            Text(evidence.sha256)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                            Text("Hash covers exactly the selected file's bytes. It is not a combined or decompressed disk-image hash.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }

                        if let hint = evidence.filesystemHint {
                            field("Filesystem Hint — Unverified", hint)
                        }

                        field("Inspected At", evidence.addedAt.formatted(date: .abbreviated, time: .standard))

                        Divider()
                        Text("This record stores file-level metadata. It does not establish filesystem contents, recoverability, or the current state of the source file.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                ContentUnavailableView {
                    Label("Select Evidence", systemImage: "info.circle")
                } description: {
                    Text("Select a recorded image to inspect its SHA-256 and file details.")
                }
            }
        }
    }

    private func field(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
