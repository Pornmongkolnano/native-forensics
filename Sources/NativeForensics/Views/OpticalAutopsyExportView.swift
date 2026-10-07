import AppKit
import Foundation
import SwiftUI

/// A source-level action: filters and row selection never narrow the export.
struct OpticalAutopsyExportView: View {
    let workspace: WorkspaceStore
    private var store: OpticalWorkspaceStore { workspace.optical }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Label("Autopsy Logical Files", systemImage: "tray.and.arrow.up")
                        .font(.caption.weight(.semibold))
                    Text("All current and historical files · verified payload hashes · new folder · 600-second limit")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Button(action: workspace.exportOpticalForAutopsy) {
                    Label("Export for Autopsy…", systemImage: "square.and.arrow.up")
                }
                .disabled(!workspace.canExportOpticalForAutopsy)
                .help("Export the complete source inventory, including files outside the current search and table page")
            }
            Text(OpticalAutopsyExportService.metadataNotice)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let reason = store.autopsyExportUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let receipt = store.lastAutopsyExport {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Verified export: \(receipt.entries.count.formatted()) files", systemImage: "checkmark.seal")
                        .font(.caption.weight(.semibold))
                    Text("In Autopsy: Add Data Source → Logical Files → select this export's LogicalFiles folder. Reports retain original paths, timestamps and historical deletion proof.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 10) {
                        Button("Show LogicalFiles") { reveal("LogicalFiles", in: receipt.destinationPath) }
                        Button("Show Reports") { reveal("Reports", in: receipt.destinationPath) }
                    }
                    .controlSize(.small)
                    Text(URL(fileURLWithPath: receipt.destinationPath).lastPathComponent)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(receipt.destinationPath)
                }
            }
        }
        .padding(10)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 8))
    }

    private func reveal(_ directory: String, in destination: String) {
        NSWorkspace.shared.activateFileViewerSelecting([
            URL(fileURLWithPath: destination, isDirectory: true).appendingPathComponent(directory, isDirectory: true)
        ])
    }
}
