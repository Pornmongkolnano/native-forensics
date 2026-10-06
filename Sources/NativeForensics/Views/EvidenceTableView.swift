import AppKit
import SwiftUI

struct EvidenceTableView: View {
    @Bindable var workspace: WorkspaceStore

    var body: some View {
        Group {
            if workspace.currentCase?.manifest.evidence.isEmpty == true {
                ContentUnavailableView {
                    Label("No Evidence Recorded", systemImage: "externaldrive")
                } description: {
                    Text("Inspect an image to save its selected file SHA-256 and byte count, then analyze its filesystem from the Filesystem section.")
                        .frame(maxWidth: 470)
                } actions: {
                    Button("Inspect Disk Image…", action: workspace.chooseImage)
                        .buttonStyle(.borderedProminent)
                        .disabled(!workspace.canInspectImage)
                }
            } else {
                Table(workspace.rows, selection: $workspace.selectedEvidenceID) {
                    TableColumn("Source File") { row in
                        Label(row.filename, systemImage: "externaldrive.fill")
                            .symbolRenderingMode(.hierarchical)
                            .lineLimit(1)
                            .help(row.record.sourcePath)
                    }
                    .width(min: 130, ideal: 220)

                    TableColumn("Size") { row in
                        Text(EvidenceFormatting.bytes(row.record.byteCount))
                            .monospacedDigit()
                    }
                    .width(min: 65, ideal: 80, max: 100)

                    TableColumn("Container") { row in
                        Text(EvidenceFormatting.container(row.record.container))
                    }
                    .width(min: 80, ideal: 110)

                    TableColumn("Selected File SHA-256") { row in
                        Text(String(row.record.sha256.prefix(16)) + "…")
                            .font(.system(.body, design: .monospaced))
                            .help(row.record.sha256)
                    }
                    .width(min: 150, ideal: 170)
                }
                .disabled(workspace.isEngineRunning)
                .searchable(text: $workspace.searchText, prompt: "Find filename or SHA-256")
                .contextMenu(forSelectionType: UUID.self) { selection in
                    if let id = selection.first,
                       let record = workspace.currentCase?.manifest.evidence.first(where: { $0.id == id }) {
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(record.sha256, forType: .string)
                        } label: {
                            Label("Copy SHA-256", systemImage: "doc.on.doc")
                        }
                        Button {
                            workspace.selectAndAnalyzeEvidence(id)
                        } label: {
                            Label("Analyze Filesystem", systemImage: "list.bullet.rectangle")
                        }
                        .disabled(workspace.isBusy)
                    }
                }
                .overlay {
                    if workspace.rows.isEmpty {
                        ContentUnavailableView.search(text: workspace.searchText)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
