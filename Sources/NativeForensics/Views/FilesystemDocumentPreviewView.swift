import AppKit
import ForensicsCore
import SwiftUI

struct FilesystemDocumentPreviewView: View {
    @Bindable var store: FilesystemDocumentPreviewStore
    var isExternallyBusy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Verified Document Preview", systemImage: "doc.text.viewfinder")
                .font(.headline)
            Text("Recovered file bytes are verified before the isolated document decoder runs. The recorded filename is preserved; the detected MIME describes the recovered content.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Button(store.analysis == nil ? "Verify and Preview" : "Verify and Reload", action: store.load)
                    .disabled(!store.canLoad || isExternallyBusy)
                if store.isLoading {
                    ProgressView().controlSize(.small)
                    Button("Cancel", action: store.cancel)
                }
            }
            Text(store.phase)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let reason = store.unavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let preview = store.preview {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Recorded Filename").font(.caption).foregroundStyle(.secondary)
                    Text(verbatim: preview.file.name).font(.callout).textSelection(.enabled)
                    Text("\(preview.receipt.byteCount.formatted()) recovered bytes · SHA-256 verified")
                        .font(.caption).foregroundStyle(.secondary)
                }
                DecodedDocumentContentView(analysis: preview.analysis, contentQuery: $store.contentQuery,
                    searchOutcome: store.searchOutcome)
            } else if !store.isLoading {
                Text("Preview supports bounded PDF, image, Office, ZIP and text content. A recovered file can retain its original extension while its bytes contain a different format.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if let error = store.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct FilesystemBatchExportView: View {
    let store: FilesystemBatchExportStore

    var body: some View {
        if store.isExporting || store.result != nil || store.errorMessage != nil {
            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Label("Batch Export", systemImage: "square.and.arrow.up.on.square")
                            .font(.headline)
                        Spacer()
                        if store.isExporting {
                            ProgressView().controlSize(.small)
                            Button("Cancel", action: store.cancel)
                        }
                    }
                    Text(store.statusMessage).font(.caption)
                    if let progress = store.progress, store.isExporting {
                        ProgressView(value: Double(progress.completedFiles), total: Double(max(1, progress.totalFiles)))
                        if let filename = progress.currentFilename {
                            Text(verbatim: filename)
                                .font(.caption2).lineLimit(1).truncationMode(.middle)
                        }
                    }
                    if let result = store.result {
                        Text("\(result.successfulCount.formatted()) / \(result.requestedCount.formatted()) files exported · \(result.failedCount.formatted()) failed")
                            .font(.caption)
                            .foregroundStyle(result.status == .completed ? Color.secondary : Color.orange)
                        Text("The manifest records original names, metadata, exported byte counts and hashes. Export success does not establish document readability.")
                            .font(.caption).foregroundStyle(.secondary)
                        Button("Show Export Folder") {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: result.destinationPath)])
                        }
                        if result.failedCount > 0 {
                            DisclosureGroup("Failed Files · \(result.failedCount.formatted())") {
                                ForEach(Array(result.entries.filter { $0.errorMessage != nil }.prefix(10).enumerated()), id: \.offset) { _, entry in
                                    Text(verbatim: "\(entry.sourceFile.path): \(entry.errorMessage ?? "Extraction failed")")
                                        .font(.caption2).foregroundStyle(.orange).textSelection(.enabled)
                                }
                                if result.failedCount > 10 {
                                    Text("Review the manifest for all failures.").font(.caption2)
                                }
                            }
                            .font(.caption)
                        }
                    }
                    if let error = store.errorMessage {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}
