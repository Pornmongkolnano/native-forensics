import AppKit
import Foundation
import SwiftUI

/// A source-level action: filters and row selection never narrow the export.
struct OpticalAutopsyExportView: View {
    let workspace: WorkspaceStore
    @State private var showsInstructions = false
    private var store: OpticalWorkspaceStore { workspace.optical }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            DisclosureGroup(isExpanded: $showsInstructions) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("All current and historical files · verified payload hashes · new folder · 600-second limit")
                        Text("In Autopsy: Add Data Source → Logical Files → select this export's LogicalFiles folder. Reports retain original paths, timestamps and historical deletion proof.")
                        Text(OpticalAutopsyExportService.metadataNotice)
                        if let receipt = store.lastAutopsyExport {
                            Text(receipt.destinationPath)
                                .font(.caption2)
                                .textSelection(.enabled)
                        }
                    }
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 92)
                .padding(.top, 6)
            } label: {
                HStack(spacing: 8) {
                    if let receipt = store.lastAutopsyExport {
                        Label("Autopsy · \(receipt.entries.count.formatted()) verified", systemImage: "checkmark.seal")
                            .fontWeight(.semibold)
                            .accessibilityLabel("Autopsy export: \(receipt.entries.count) verified files")
                    } else {
                        Label("Autopsy Logical Files", systemImage: "tray.and.arrow.up")
                            .fontWeight(.semibold)
                    }
                    Spacer(minLength: 0)
                    Button(action: workspace.exportOpticalForAutopsy) {
                        Label(store.lastAutopsyExport == nil ? "Export for Autopsy…" : "Export…", systemImage: "square.and.arrow.up")
                    }
                    .disabled(!workspace.canExportOpticalForAutopsy)
                    .accessibilityLabel("Export for Autopsy…")
                    .help("Export the complete source inventory, including files outside the current search and table page")
                    if let receipt = store.lastAutopsyExport {
                        Button("Show LogicalFiles") { reveal("LogicalFiles", in: receipt.destinationPath) }
                        Button("Show Reports") { reveal("Reports", in: receipt.destinationPath) }
                    }
                }
                .controlSize(.mini)
            }
            .font(.caption)
            .help("Show import instructions and export details")
            Text("UDF times/deletion: Reports. Autopsy host timestamps: off.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let reason = store.autopsyExportUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 4)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 8))
    }

    private func reveal(_ directory: String, in destination: String) {
        NSWorkspace.shared.activateFileViewerSelecting([
            URL(fileURLWithPath: destination, isDirectory: true).appendingPathComponent(directory, isDirectory: true)
        ])
    }
}
