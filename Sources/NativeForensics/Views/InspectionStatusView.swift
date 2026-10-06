import SwiftUI

struct InspectionStatusView: View {
    let workspace: WorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if workspace.isEngineRunning {
                HStack {
                    Text(workspace.engineOperationLabel).lineLimit(1)
                    Spacer()
                    Button("Cancel", action: workspace.cancelEngineJob)
                        .controlSize(.small)
                }
                if let progress = workspace.verificationProgress {
                    ProgressView(value: progress.fraction)
                    Text("Source verification: \(EvidenceFormatting.bytes(progress.bytesRead)) of \(EvidenceFormatting.bytes(progress.totalBytes))")
                        .font(.caption)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                } else if let progress = workspace.engineProgress {
                    if let total = progress.total, total > 0 {
                        ProgressView(value: min(1, max(0, Double(progress.completed) / Double(total))))
                    } else {
                        ProgressView().controlSize(.small)
                    }
                    Text("\(progress.stage): \(progress.completed)\(progress.total.map { " of \($0)" } ?? "") \(progress.unit)")
                        .font(.caption)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                } else {
                    ProgressView().controlSize(.small)
                }
            } else if workspace.isInspecting {
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
            } else if workspace.isLoadingFilesystem {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Loading saved filesystem result…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
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
