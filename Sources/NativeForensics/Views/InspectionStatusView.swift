import SwiftUI

struct InspectionStatusView: View {
    let workspace: WorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if workspace.filesystemBatchExport.isExporting {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(workspace.filesystemBatchExport.statusMessage).lineLimit(1)
                    Spacer()
                    Button("Cancel", action: workspace.filesystemBatchExport.cancel)
                }
            } else if workspace.filesystemDocumentPreview.isLoading {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(workspace.filesystemDocumentPreview.phase).lineLimit(1)
                    Spacer()
                    Button("Cancel", action: workspace.filesystemDocumentPreview.cancel)
                }
            } else if workspace.optical.isInspecting || workspace.optical.isPreviewing || workspace.optical.isExporting || workspace.optical.isExportingReport || workspace.optical.isExportingAutopsy {
                OpticalStatusView(store: workspace.optical)
            } else if workspace.recovery.examination.hasActiveWork {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(workspace.recovery.examination.statusMessage).lineLimit(1)
                    Spacer()
                    Button("Cancel", action: workspace.recovery.examination.cancel)
                }
            } else if workspace.recovery.isRecovering || workspace.recovery.isPreviewing || workspace.recovery.isExporting {
                RecoveryStatusView(store: workspace.recovery)
            } else if workspace.isEngineRunning {
                HStack(spacing: 8) {
                    Image(systemName: "gearshape.2")
                        .foregroundStyle(.secondary)
                    Text(workspace.engineOperationLabel)
                        .lineLimit(1)
                        .help(workspace.engineOperationLabel)
                    Spacer(minLength: 8)
                    Button("Cancel", action: workspace.cancelEngineJob)
                        .help("Cancel this job (⌘.)")
                }
                HStack(spacing: 12) {
                    if let progress = workspace.verificationProgress {
                        ProgressView(value: progress.fraction)
                            .frame(maxWidth: 180)
                        Text("Source verification: \(EvidenceFormatting.bytes(progress.bytesRead)) of \(EvidenceFormatting.bytes(progress.totalBytes))")
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    } else if let progress = workspace.engineProgress {
                        if let fraction = progress.fraction {
                            ProgressView(value: fraction)
                                .frame(maxWidth: 180)
                        } else {
                            ProgressView().controlSize(.small)
                        }
                        Text("\(progress.stage): \(progress.completed.formatted())\(progress.total.map { " of \($0.formatted())" } ?? "") \(progress.unit)")
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    } else {
                        ProgressView().controlSize(.small)
                    }
                    Spacer(minLength: 0)
                }
            } else if workspace.isInspecting {
                HStack(spacing: 8) {
                    Image(systemName: "externaldrive")
                        .foregroundStyle(.secondary)
                    Text("Inspecting \(workspace.inspectionFilename ?? "image")")
                        .lineLimit(1)
                    Spacer(minLength: 8)
                    Button("Cancel", action: workspace.cancelInspection)
                        .help("Cancel inspection (⌘.)")
                }
                HStack(spacing: 12) {
                    if let progress = workspace.progress {
                        ProgressView(value: progress.fraction)
                            .frame(maxWidth: 180)
                        Text("\(EvidenceFormatting.bytes(progress.bytesRead)) of \(EvidenceFormatting.bytes(progress.totalBytes))")
                            .foregroundStyle(.secondary)
                        Spacer(minLength: 0)
                        Text(progress.fraction, format: .percent.precision(.fractionLength(0)))
                            .foregroundStyle(.secondary)
                    } else {
                        ProgressView().controlSize(.small)
                        Spacer(minLength: 0)
                    }
                }
                .monospacedDigit()
            } else if workspace.contentPreview.isLoading {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(workspace.contentPreview.phase).foregroundStyle(.secondary).lineLimit(1)
                    Spacer()
                    Button("Cancel", action: workspace.contentPreview.cancel)
                }
            } else if workspace.caseWork.hasActivePublication {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(workspace.caseWork.statusMessage).foregroundStyle(.secondary).lineLimit(1)
                    Spacer()
                }
            } else if workspace.isLoadingFilesystem {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Loading saved filesystem result…")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
            } else {
                HStack(spacing: 8) {
                    Image(systemName: "lock.shield")
                        .foregroundStyle(.secondary)
                    Text(workspace.statusMessage)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .help(workspace.statusMessage)
                    Spacer(minLength: 0)
                }
            }
        }
        .font(.caption)
        .controlSize(.small)
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .background(.bar)
    }
}
