import SwiftUI

struct InspectionStatusView: View {
    let workspace: WorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if workspace.isInspecting {
                HStack {
                    Text("Inspecting \(workspace.inspectionFilename ?? "image")")
                        .lineLimit(1)
                    Spacer()
                    Button("Cancel", action: workspace.cancelInspection)
                        .controlSize(.small)
                }
                if let progress = workspace.progress {
                    ProgressView(value: progress.fraction)
                    HStack {
                        Text("\(EvidenceFormatting.bytes(progress.bytesRead)) of \(EvidenceFormatting.bytes(progress.totalBytes))")
                        Spacer()
                        Text(progress.fraction, format: .percent.precision(.fractionLength(0)))
                    }
                    .monospacedDigit()
                    .font(.caption)
                    .foregroundStyle(.secondary)
                } else {
                    ProgressView().controlSize(.small)
                }
            } else {
                HStack(spacing: 8) {
                    Image(systemName: "info.circle")
                        .foregroundStyle(.secondary)
                    Text(workspace.statusMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                    Spacer(minLength: 0)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}
